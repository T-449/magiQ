import json
import os
import time

from lib.common import (
    sha256_hex, b64e, b64d, keys_dir, certs_dir, save_bytes, save_json,
    safe_name, build_tuple_message, load_config, ROOT_DIR,
    build_merkle_tree, icp_time_leaf,
)
from lib.crypto import MLDSAWrapper, XMSS_ALGO, MLDSA_ALGO
from lib.metrics import print_crypto_costs, print_bandwidth_costs
from agent import Agent

_CFG = load_config()


class User:

    def __init__(self, user_data, xmss, tls_client, tls_paths, agent_cls=Agent):
        self.uid = user_data["uid"]
        self.password = user_data["password"]
        self._agent_defs = user_data.get("agents", [])
        self._xmss = xmss
        self._tls = tls_client
        self._tls_paths = tls_paths
        self._agent_cls = agent_cls

        self.xmss_handle = None
        self.id_pk = None
        self.cert_u = None

        self._provider_tls_pk = None
        self._provider_id_pk = None

        self.agents = {}
        self._agent_keys = {}

        self._agent_policies = {}
        self._safe = safe_name(self.uid)

    def register(self, ca):
        """Generate the user identity key, get a cert, register with provider."""
        costs = {}

        print(f"[USER:{self.uid}] Generating XMSS identity keys ({XMSS_ALGO}) ...")
        t0 = time.perf_counter()
        self.xmss_handle, self.id_pk = self._xmss.keygen()
        costs["XMSS keygen (user identity)"] = time.perf_counter() - t0

        kd = keys_dir("users", self._safe)
        save_bytes(self.id_pk, f"{kd}/xmss_id_pk.bin")
        print(f"[USER:{self.uid}] OK pk={len(self.id_pk)}B "
              f"fp={sha256_hex(self.id_pk)[:16]}...")

        print(f"[USER:{self.uid}] Requesting cert from CA ...")
        t0 = time.perf_counter()
        self.cert_u = ca.issue_cert(self.uid, self.id_pk, XMSS_ALGO)
        costs["ML-DSA-65 sign (CA issues user cert)"] = time.perf_counter() - t0
        save_json(self.cert_u, f"{certs_dir('users', self._safe)}/identity.json")

        print(f"[USER:{self.uid}] Obtaining provider info from CA ...")
        prov_info = ca.get_provider_info()

        t0 = time.perf_counter()
        if not ca.verify_cert(prov_info["tls_cert"]):
            raise RuntimeError("Provider TLS cert verification failed")
        costs["ML-DSA-65 verify (provider TLS cert)"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        if not ca.verify_cert(prov_info["id_cert"]):
            raise RuntimeError("Provider identity cert verification failed")
        costs["ML-DSA-65 verify (provider ID cert)"] = time.perf_counter() - t0

        self._provider_tls_pk = prov_info["tls_pk"]
        self._provider_id_pk = prov_info["id_pk"]
        print(f"[USER:{self.uid}] OK Provider certs verified (from CA)")

        print(f"[USER:{self.uid}] Sending registration to provider over TLS ...")
        resp = self._tls.request({
            "action": "register_user",
            "uid": self.uid,
            "password": self.password,
            "cert_u": self.cert_u,
        })
        bw = self._tls.pop_last_request_bandwidth()
        if bw:
            print_bandwidth_costs(f"User Reg ({self.uid})",
                                  {"register_user": bw},
                                  src_label="user", dst_label="provider")

        if not (resp and resp.get("success")):
            message = resp.get("message", "?") if resp else "no response"
            raise RuntimeError(f"Registration failed: {message}")
        print(f"[USER:{self.uid}] OK Registered with provider")

        print_crypto_costs(f"User Registration: {self.uid}",
                           costs, resp.get("crypto_timing", {}),
                           local_label="User")

    def register_agents(self, ca):
        if not self._agent_defs:
            print(f"[USER:{self.uid}] No agents to register")
            return
        for agent_def in self._agent_defs:
            aid = f"{self.uid}:{agent_def['name']}"
            print(f"\n--- Agent: {aid} ---")
            policy = self._load_policy(agent_def.get("policy_file"))
            self._agent_policies[aid] = policy
            agent = self._agent_cls({"user_uid": self.uid, **agent_def}, policy)
            self._register_agent(agent, ca)
            agent.setup(self._tls, self, ca, self._provider_id_pk,
                        self._tls_paths)
            self.agents[aid] = agent

    def _load_policy(self, policy_file):
        if not policy_file:
            return {}
        path = os.path.join(ROOT_DIR, _CFG["paths"]["data_policies"], policy_file)
        with open(path) as f:
            return json.load(f)

    def _register_agent(self, agent, ca):
        costs = {}
        aid = agent.aid

        if self._provider_tls_pk is None:
            raise RuntimeError("Register user first")

        print(f"[USER:{self.uid}] Generating agent ML-DSA-65 TLS keys ...")
        t0 = time.perf_counter()
        mldsa = MLDSAWrapper()
        agent.tls_pk, agent_tls_sk = mldsa.keygen()
        costs["ML-DSA-65 keygen (agent TLS)"] = time.perf_counter() - t0

        print(f"[USER:{self.uid}] Requesting agent cert from CA ...")
        t0 = time.perf_counter()
        agent.cert_a = ca.issue_cert(aid, agent.tls_pk, MLDSA_ALGO)
        costs["ML-DSA-65 sign (CA issues agent cert)"] = time.perf_counter() - t0

        print(f"[USER:{self.uid}] Generating agent XMSS identity keys ...")
        t0 = time.perf_counter()
        agent_id_handle, agent.id_pk = self._xmss.keygen()
        costs["XMSS keygen (agent identity)"] = time.perf_counter() - t0

        print(f"[USER:{self.uid}] Signing agent identity (sigma_ID) ...")
        t0 = time.perf_counter()
        agent.sig_id = self._xmss.sign(
            self.xmss_handle, build_tuple_message(aid, agent.id_pk))
        costs["XMSS sign sigma_ID"] = time.perf_counter() - t0

        print(f"[USER:{self.uid}] Signing agent metadata (sigma_A) ...")
        t0 = time.perf_counter()
        agent.sig_a = self._xmss.sign(
            self.xmss_handle,
            build_tuple_message(aid, agent.ed_bytes(), agent.tls_pk,
                                self._provider_tls_pk, self._provider_id_pk))
        costs["XMSS sign sigma_A"] = time.perf_counter() - t0

        print(f"[USER:{self.uid}] Submitting to provider over TLS ...")
        resp = self._tls.request({
            "action": "register_agent",
            "uid": self.uid,
            "password": self.password,
            "aid": aid,
            "ed": agent.ed,
            "cp": agent.cp,
            "cert_a": agent.cert_a,
            "id_pk_a_b64": b64e(agent.id_pk),
            "sig_id_b64": b64e(agent.sig_id),
            "sig_a_b64": b64e(agent.sig_a),
        })
        bw = self._tls.pop_last_request_bandwidth()
        if bw:
            print_bandwidth_costs(f"Agent Reg ({aid})",
                                  {"register_agent": bw},
                                  src_label="user", dst_label="provider")

        if not (resp and resp.get("success")):
            message = resp.get("message", "?") if resp else "no response"
            raise RuntimeError(f"Agent registration failed: {message}")

        agent.sig_ta = b64d(resp["sig_ta_b64"])
        print(f"[USER:{self.uid}] OK Provider accepted "
              f"(sig_ta={len(agent.sig_ta)}B)")

        print(f"[USER:{self.uid}] Verifying provider countersig ...")
        t0 = time.perf_counter()
        msg_ta = build_tuple_message(aid, agent.cert_bytes(), agent.ed_bytes(),
                                     agent.id_pk, agent.sig_a)
        if not self._xmss.verify(msg_ta, agent.sig_ta, self._provider_id_pk):
            raise RuntimeError("Provider countersig verification FAILED")
        costs["XMSS verify sigma_TA"] = time.perf_counter() - t0
        print(f"[USER:{self.uid}] OK Provider countersig valid")

        self._agent_keys[aid] = {"xmss_handle": agent_id_handle,
                                 "tls_sk": agent_tls_sk}
        agent.save()

        print_crypto_costs(f"Agent Registration: {aid}",
                           costs, resp.get("crypto_timing", {}),
                           local_label="User")

    def agent_xmss_sign(self, aid, message):
        keys = self._agent_keys.get(aid)
        if not keys:
            raise RuntimeError(f"No keys held for agent {aid}")
        return self._xmss.sign(keys["xmss_handle"], message)

    @staticmethod
    def read_clock():
        """Read the current time. Models a single-host clock with zero skew."""
        return int(time.time())

    def _policy_for(self, aid):
        policy = self._agent_policies.get(aid)
        if policy is None:
            raise RuntimeError(f"User {self.uid}: no policy held for '{aid}'")
        return policy

    def _sign_session_token(self, aid, chain_root, q, delta, q_max, delta_max,
                            label):
        if self.xmss_handle is None:
            raise RuntimeError(f"User {self.uid}: no XMSS keys")
        q, delta = int(q), int(delta)
        if not 0 < q <= q_max:
            raise RuntimeError(
                f"User {self.uid}: refusing to sign {label} for {aid}: "
                f"Q={q} outside policy (max {q_max})")
        if not 0 < delta <= delta_max:
            raise RuntimeError(
                f"User {self.uid}: refusing to sign {label} for {aid}: "
                f"Delta={delta}s outside policy (max {delta_max}s)")
        tau_start = self.read_clock()
        sig = self._xmss.sign(
            self.xmss_handle,
            build_tuple_message(chain_root, tau_start, q, delta))
        print(f"[USER:{self.uid}] OK {label} issued for {aid} "
              f"(Q={q}, Delta={delta}s, tau_start={tau_start})")
        return sig, tau_start

    def user_sign_rcp(self, aid, chain_root, q, delta):
        """Responder token, checked against the agent's RCP."""
        rcp = self._policy_for(aid).get("rcp", {})
        return self._sign_session_token(
            aid, chain_root, q, delta,
            int(rcp["Q"]), int(rcp["delta_sec"]), "tok^msg+Time (RCP)")

    def user_sign_icp_two_agent(self, aid, chain_root, q, delta):
        """Initiator token in the two-agent case, where ICP behaves like RCP."""
        icp = self._policy_for(aid).get("icp", {})
        return self._sign_session_token(
            aid, chain_root, q, delta,
            int(icp["n_prime"]), int(icp["delta_tot_sec"]),
            "tok^msg+Time (ICP, 2-agent)")

    def user_sign_icp(self, aid, chain_roots, deltas, n_prime):
        """Sign the merged C-session ICP token for a static workflow plan."""
        if self.xmss_handle is None:
            raise RuntimeError(f"User {self.uid}: no XMSS keys")
        icp = self._policy_for(aid).get("icp", {})
        q_tot = int(icp["Q_tot"])
        delta_tot = int(icp["delta_tot_sec"])
        n_prime = int(n_prime)
        m, t = len(chain_roots), len(deltas)

        if m < 1 or t < 1:
            raise RuntimeError(f"User {self.uid}: empty ICP request for {aid}")
        if m * n_prime > q_tot:
            raise RuntimeError(
                f"User {self.uid}: refusing to sign ICP for {aid}: "
                f"m*n' = {m}*{n_prime} = {m * n_prime} exceeds Q_tot={q_tot}")
        if any(int(d) <= 0 for _, d in deltas):
            raise RuntimeError(
                f"User {self.uid}: refusing to sign ICP for {aid}: "
                "non-positive per-session time budget")
        delta_sum = sum(int(d) for _, d in deltas)
        if delta_sum > delta_tot:
            raise RuntimeError(
                f"User {self.uid}: refusing to sign ICP for {aid}: "
                f"sum(Delta_j) = {delta_sum}s exceeds Delta_tot={delta_tot}s")

        root_msg, _ = build_merkle_tree(list(chain_roots))
        root_time, _ = build_merkle_tree(
            [icp_time_leaf(j, peer, d) for j, (peer, d) in enumerate(deltas)])

        tau_start = self.read_clock()
        sig = self._xmss.sign(
            self.xmss_handle,
            build_tuple_message(root_msg, root_time, tau_start,
                                n_prime, m, t, q_tot, delta_tot))
        print(f"[USER:{self.uid}] OK ICP token issued for {aid} "
              f"(m={m}, t={t}, n'={n_prime}, Q_tot={q_tot}, "
              f"sum(Delta_j)={delta_sum}<={delta_tot}s, tau_start={tau_start})")
        return sig, tau_start, root_msg, root_time
