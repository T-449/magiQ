"""
user.py - User operations
=========================
The User defines, creates, and registers its own agents.
The User is the key custodian - performs all crypto on behalf of agents.
"""

import json
import os
import time

from lib.common import (
    sha256_hex, keys_dir, certs_dir, save_bytes, save_json, safe_name,
    build_tuple_message, load_config, ROOT_DIR, print_crypto_costs,
    print_bandwidth_costs,
)
from lib.crypto import MLDSAWrapper, XMSS_ALGO, MLDSA_ALGO
from agent import Agent

_CFG = load_config()


class User:

    def __init__(self, user_data, xmss, tls_client, tls_paths, agent_cls=Agent):
        self.uid          = user_data["uid"]
        self.password     = user_data["password"]
        self._agent_defs  = user_data.get("agents", [])
        self._xmss        = xmss
        self._tls         = tls_client
        self._tls_paths   = tls_paths
        self._agent_cls   = agent_cls

        self.xmss_handle  = None
        self.id_pk        = None
        self.cert_u       = None

        self._provider_tls_pk = None
        self._provider_id_pk  = None

        self.agents       = {}   # aid -> Agent
        self._agent_keys  = {}   # aid -> {xmss_handle, tls_sk}
        self._safe        = safe_name(self.uid)

    #  Phase 1 - User Registration
    def register(self, ca):
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
        self._provider_id_pk  = prov_info["id_pk"]
        print(f"[USER:{self.uid}] OK Provider certs verified (from CA)")

        print(f"[USER:{self.uid}] Sending registration to provider over TLS ...")
        resp = self._tls.request({
            "action":   "register_user",
            "uid":      self.uid,
            "password": self.password,
            "cert_u":   self.cert_u,
        })
        bw = self._tls.pop_last_request_bandwidth()
        if bw:
            print_bandwidth_costs(
                f"User Reg ({self.uid})",
                {"register_user": bw},
                src_label="user",
                dst_label="provider",
            )

        if not (resp and resp.get("success")):
            raise RuntimeError(
                f"Registration failed: {resp.get('message', '?') if resp else 'no response'}")
        print(f"[USER:{self.uid}] OK Registered with provider")

        print_crypto_costs(f"User Registration: {self.uid}",
                           costs, resp.get("crypto_timing", {}),
                           local_label="User")

    #  Phase 2 - Agent Registration
    def register_agents(self, ca):
        if not self._agent_defs:
            print(f"[USER:{self.uid}] No agents to register")
            return
        for ad in self._agent_defs:
            aid        = f"{self.uid}:{ad['name']}"
            print(f"\n--- Agent: {aid} ---")
            agent_data = {"user_uid": self.uid, **ad}
            policy     = self._load_policy(ad.get("policy_file"))
            ag         = self._agent_cls(agent_data, policy)
            self._register_agent(ag, ca)
            ag.setup(self._tls, self, ca, self._provider_id_pk, self._tls_paths)
            self.agents[aid] = ag

    def _load_policy(self, policy_file):
        if not policy_file:
            return {}
        path = os.path.join(ROOT_DIR, _CFG["paths"]["data_policies"], policy_file)
        with open(path) as f:
            return json.load(f)

    def _register_agent(self, agent, ca):
        costs = {}
        aid   = agent.aid

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
            "action":     "register_agent",
            "uid":        self.uid,
            "password":   self.password,
            "aid":        aid,
            "ed":         agent.ed,
            "cp":         agent.cp,
            "cert_a":     agent.cert_a,
            "id_pk_a_hex": agent.id_pk.hex(),
            "sig_id_hex": agent.sig_id.hex(),
            "sig_a_hex":  agent.sig_a.hex(),
        })
        bw = self._tls.pop_last_request_bandwidth()
        if bw:
            print_bandwidth_costs(
                f"Agent Reg ({aid})",
                {"register_agent": bw},
                src_label="user",
                dst_label="provider",
            )

        if not (resp and resp.get("success")):
            raise RuntimeError(
                f"Agent registration failed: "
                f"{resp.get('message', '?') if resp else 'no response'}")

        agent.sig_ta = bytes.fromhex(resp["sig_ta_hex"])
        print(f"[USER:{self.uid}] OK Provider accepted (sig_ta={len(agent.sig_ta)}B)")

        print(f"[USER:{self.uid}] Verifying provider countersig ...")
        t0 = time.perf_counter()
        msg_ta = build_tuple_message(
            aid, agent.cert_bytes(), agent.ed_bytes(), agent.id_pk, agent.sig_a)
        if not self._xmss.verify(msg_ta, agent.sig_ta, self._provider_id_pk):
            raise RuntimeError("Provider countersig verification FAILED")
        costs["XMSS verify sigma_TA"] = time.perf_counter() - t0
        print(f"[USER:{self.uid}] OK Provider countersig valid")

        self._agent_keys[aid] = {"xmss_handle": agent_id_handle,
                                  "tls_sk":      agent_tls_sk}
        agent.save()

        print_crypto_costs(f"Agent Registration: {aid}",
                           costs, resp.get("crypto_timing", {}),
                           local_label="User")

    #  Key operations on behalf of agents
    def agent_xmss_sign(self, aid, message):
        keys = self._agent_keys.get(aid)
        if not keys:
            raise RuntimeError(f"No keys held for agent {aid}")
        return self._xmss.sign(keys["xmss_handle"], message)

    def agent_tls_sk(self, aid):
        keys = self._agent_keys.get(aid)
        if not keys:
            raise RuntimeError(f"No keys held for agent {aid}")
        return keys["tls_sk"]

    def user_xmss_sign(self, message):
        if self.xmss_handle is None:
            raise RuntimeError(f"User {self.uid}: no XMSS keys")
        return self._xmss.sign(self.xmss_handle, message)

    def user_sign_icp(self, orchestrator_aid, m_root, delta_tot_sec):
        """Sign MA ICP binding tuple and return (signature, expiry_epoch_sec)."""
        if self.xmss_handle is None:
            raise RuntimeError(f"User {self.uid}: no XMSS keys")
        t_exp = int(time.time()) + int(delta_tot_sec)
        msg = build_tuple_message(str(t_exp), orchestrator_aid,
                                  m_root, str(delta_tot_sec))
        return self._xmss.sign(self.xmss_handle, msg), t_exp

