import socket
import threading
import time
from collections import defaultdict

from lib.agent_session import AgentSession
from lib.common import (
    certs_dir, save_json, safe_name, build_tuple_message,
    create_key, prf, sha256, canonical_json, b64e, b64d,
    personalized_hash_chain, verify_chain_element, verify_chain_step,
    prf_verify,
)
from lib.crypto import pk_from_cert
from lib.metrics import print_crypto_costs, print_bandwidth_costs
from lib.tls_channel import (
    send_msg, recv_msg, make_client_context, make_server_context,
    make_listening_socket, open_tls_client,
)

AGENT_SESSION_TIMEOUT_SEC = 900


class Agent:

    def __init__(self, agent_data, policy):
        self.user_uid = agent_data["user_uid"]
        self.name = agent_data["name"]
        self.aid = f"{self.user_uid}:{self.name}"
        self.ed = {
            "device": agent_data["device"],
            "ip": agent_data["ip"],
            "port": agent_data["port"],
        }
        self.cp = policy
        self.tool = agent_data.get("tool")
        self._app_agent = None

        self.tls_pk = None
        self.id_pk = None
        self.cert_a = None
        self.sig_id = None
        self.sig_a = None
        self.sig_ta = None

        self._tls = None
        self._user = None
        self._ca = None
        self._provider_id_pk = None
        self._tls_paths = None
        self._xmss = None

        self._listener_sock = None
        self._listener_thread = None
        self._listener_running = False
        self._listener_ctx = None
        self._pending_sessions = []
        self._pending_lock = threading.Lock()
        self._pending_event = threading.Event()

        self.contacts = {}
        self._session_state = {}
        self._safe = safe_name(self.aid)

        self._llm_total_calls = 0
        self._llm_total_sec = 0.0
        self._llm_by_label = defaultdict(lambda: {"calls": 0, "sec": 0.0})

    def setup(self, tls_client, user, ca, provider_id_pk, tls_paths):
        self._tls = tls_client
        self._user = user
        self._ca = ca
        self._provider_id_pk = provider_id_pk
        self._tls_paths = tls_paths
        self.start_listener()

    def handle_message(self, session, msg):
        """Route one message received over an agent-to-agent session."""
        msg_type = msg.get("type")
        print(f"[AGENT:{self.aid}] handle_message: type={msg_type}")
        if msg_type == "handshake_init":
            return self._on_handshake_init(session, msg)
        if msg_type == "handshake_resp":
            return self._on_handshake_resp(session, msg)
        if msg_type == "data_request":
            return self._on_data_request(session, msg)
        if msg_type == "data_response":
            return self._on_data_response(session, msg)
        print(f"[AGENT:{self.aid}] Unknown message type: {msg_type}")
        return None

    def start_A_session(self, target_aid, xmss):
        """Contact the provider, open PQ-TLS, send m_0 and verify m_1."""
        self._xmss = xmss
        contact_info = self.initiate_contact(target_aid, xmss)

        print(f"\n[AGENT:{self.aid}] === PQ-TLS to {target_aid} ===")
        session = self._connect_to_agent(contact_info)
        print(f"[AGENT:{self.aid}] OK PQ-TLS established")

        hs_state = self._handshake_initiator(session, contact_info)
        resp_msg = session.recv()
        if resp_msg is None:
            raise RuntimeError("handshake response not received")
        resp_state = self.handle_message(session, resp_msg)

        return {
            "session": session,
            "role": "initiator",
            "local_aid": self.aid,
            "remote_aid": contact_info["aid_r"],
            "k_sess": resp_state["k_sess"],
            "q_ir": hs_state["q_ir"],
            "delta_ir": hs_state["delta_ir"],
            "q_ri": resp_state["q_ri"],
            "delta_ri": resp_state["delta_ri"],
            "res_1": resp_state["res_1"],
            "session_expiry": resp_state["session_expiry"],
        }

    def verify_sig_ta_ac(self, sig_ta_ac, aid_i, id_pk_i):
        t_exp = self.cp.get("expiry", "2099-01-01T00:00:00Z")
        msg = build_tuple_message(
            t_exp,
            canonical_json(self._user.cert_u),
            self.aid,
            self.ed_bytes(),
            self.cert_bytes(),
            self.id_pk,
            self.tls_pk,
            self.sig_id,
            self.sig_a,
            aid_i,
            id_pk_i,
        )
        if not self._xmss.verify(msg, sig_ta_ac, self._provider_id_pk):
            raise RuntimeError("sigma^TA_ac verification failed")
        print(f"[AGENT:{self.aid}] OK sigma^TA_ac valid ({len(sig_ta_ac)}B)")

    def _handshake_initiator(self, session, contact_info):
        """Build and send m_0, then stash the state needed to verify m_1."""
        aid_r = contact_info["aid_r"]
        t_exp = contact_info["t_exp"]
        print(f"\n[AGENT:{self.aid}] === Handshake (initiator) ===")

        icp = self.cp.get("icp", {})
        if not any(c.get("peer_aid") == aid_r
                   for c in icp.get("allowed_contacts", [])):
            raise RuntimeError(f"{aid_r} not in ICP allowed_contacts")
        q_ir = int(icp["n_prime"])
        delta_ir = int(icp["delta_tot_sec"])

        costs = {}

        k_1 = create_key()
        t0 = time.perf_counter()
        seed = prf(k_1, self.aid, aid_r, 0)
        chain = personalized_hash_chain(seed, q_ir, aid_r.encode())
        costs[f"PRF seed + hash chain (n'={q_ir})"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] Generated k_1 ({len(k_1)}B), "
              f"chain built (n'={q_ir}, root={chain[q_ir].hex()[:16]}...)")

        t0 = time.perf_counter()
        sig_u_cp, tau_start = self._user.user_sign_icp_two_agent(
            self.aid, chain[q_ir], q_ir, delta_ir)
        costs["XMSS sign tok^msg+Time (ICP)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK tok^msg+Time signed "
              f"(tau_start={tau_start})")

        m_0 = {
            "k_1_b64": b64e(k_1),
            "info_ai": {
                "cert_u_i": self._user.cert_u,
                "aid_i": self.aid,
                "ed_i": self.ed,
                "cert_a_i": self.cert_a,
                "id_pk_i_b64": b64e(self.id_pk),
                "pk_i_b64": b64e(self.tls_pk),
                "sig_id_b64": b64e(self.sig_id),
                "sig_a_b64": b64e(self.sig_a),
            },
            "Q_ir": q_ir,
            "delta_ir": delta_ir,
            "tau_start": tau_start,
            "next_tok": {"image_b64": b64e(chain[q_ir]),
                         "preimage_b64": b64e(chain[q_ir - 1])},
        }

        t0 = time.perf_counter()
        sig_init = self.request_signature(canonical_json(m_0))
        costs["XMSS sign sigma^A_I_init"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^A_I_init signed")

        session.send({
            "type": "handshake_init",
            "m_0": m_0,
            "sig_ta_ac_b64": b64e(contact_info["sig_ta_ac"]),
            "sig_init_b64": b64e(sig_init),
            "sig_u_cp_b64": b64e(sig_u_cp),
        })
        print(f"[AGENT:{self.aid}] OK Handshake sent to {aid_r}")
        print_crypto_costs(f"Handshake Init: {self.aid}", costs)

        self._session_state[aid_r] = {
            "role": "initiator",
            "remote_aid": aid_r,
            "t_exp": t_exp,
            "tau_start": tau_start,
            "k_1": k_1,
            "chain_i": chain,
            "q_ir": q_ir,
            "delta_ir": delta_ir,
            "ctr_icp": q_ir - 1,
            "last_rho_released_idx": q_ir - 1,
            "pk_u_r": contact_info["pk_u_r"],
            "session_expiry": time.time() + delta_ir,
            "round_num": 1,
        }
        return {"q_ir": q_ir, "delta_ir": delta_ir}

    def _on_handshake_resp(self, session, msg):
        """Initiator side: verify m_1 and fix the effective session expiry."""
        aid_r = session.remote_aid
        state = self._session_state.get(aid_r)
        if state is None or state["role"] != "initiator":
            raise RuntimeError(f"No initiator state for {aid_r}")

        costs = {}
        m_1 = msg["m_1"]
        tag_1 = b64d(msg["tag_1_b64"])
        k_2 = b64d(m_1["k_2_b64"])

        t0 = time.perf_counter()
        k_sess = sha256(state["k_1"] + k_2)
        costs["SHA-256 k_sess derivation"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        if not prf_verify(k_sess, canonical_json(m_1), tag_1):
            raise RuntimeError("tag_1 verification failed")
        costs["HMAC-SHA256 verify tag_1"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK tag_1 valid")

        if b64d(m_1["next_tok_i"]["preimage_b64"]) \
                != state["chain_i"][state["q_ir"] - 1]:
            raise RuntimeError("NextTok^ICP_1 echo mismatch")
        print(f"[AGENT:{self.aid}] OK NextTok^ICP_1 echo valid")

        sig_u_r_cp = b64d(m_1["sig_u_r_cp_b64"])
        s_n = b64d(m_1["next_tok_r"]["image_b64"])
        s_n_minus_1 = b64d(m_1["next_tok_r"]["preimage_b64"])
        q_ri = int(m_1["Q_ri"])
        delta_ri = int(m_1["delta_ri"])
        tau_start_r = int(m_1["tau_start_r"])

        t0 = time.perf_counter()
        if not self._xmss.verify(
                build_tuple_message(s_n, tau_start_r, q_ri, delta_ri),
                sig_u_r_cp, state["pk_u_r"]):
            raise RuntimeError("tok^msg+Time (RCP) verification failed")
        costs["XMSS verify tok^msg+Time (RCP)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK tok^msg+Time (RCP) valid")

        tau_now = int(time.time())
        if not tau_now - tau_start_r < delta_ri:
            raise RuntimeError(
                f"RCP time budget already elapsed: tau_now - tau'_start = "
                f"{tau_now - tau_start_r}s >= Delta_RI = {delta_ri}s")
        print(f"[AGENT:{self.aid}] OK RCP time window valid "
              f"({tau_now - tau_start_r}s of {delta_ri}s elapsed)")

        t0 = time.perf_counter()
        if not verify_chain_step(s_n_minus_1, q_ri, self.aid.encode(), s_n):
            raise RuntimeError("s_n chain-step verification failed")
        costs["SHA-256 chain-step verify (s_n)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK s_n chain-step valid")

        delta_eff = min(int(state["delta_ir"]), delta_ri)
        state.update({
            "k_2": k_2, "k_sess": k_sess,
            "q_ri": q_ri, "delta_ri": delta_ri,
            "tau_start_r": tau_start_r,
            "chain_r_image": s_n,
            "last_s_seen": s_n_minus_1,
            "last_s_seen_idx": q_ri - 1,
            "ctr_rcp": q_ri - 1,
            "session_expiry": tau_now + delta_eff,
            "res_1": m_1["res_1"],
        })
        print(f"[AGENT:{self.aid}] Session expiry = tau_now + "
              f"min({state['delta_ir']}, {delta_ri}) = {delta_eff}s")
        print(f"[AGENT:{self.aid}] OK Handshake response verified "
              f"(Q_RI={q_ri} DELTA_RI={delta_ri}s)")
        print_crypto_costs(f"Handshake Resp Verify: {self.aid}", costs)

        return {
            "k_sess": k_sess,
            "q_ri": q_ri,
            "delta_ri": delta_ri,
            "res_1": m_1["res_1"],
            "session_expiry": state["session_expiry"],
        }

    def _on_handshake_init(self, session, msg):
        """Receiver side: verify m_0 and reply with m_1."""
        aid_i = session.remote_aid
        print(f"\n[AGENT:{self.aid}] === Handshake (receiver from {aid_i}) ===")

        m_0 = msg["m_0"]
        sig_ta_ac = b64d(msg["sig_ta_ac_b64"])
        sig_init = b64d(msg["sig_init_b64"])
        sig_u_cp = b64d(msg["sig_u_cp_b64"])

        info = m_0["info_ai"]
        q_ir = m_0["Q_ir"]
        delta_ir = m_0["delta_ir"]
        next_tok = m_0["next_tok"]
        k_1 = b64d(m_0["k_1_b64"])
        id_pk_i = b64d(info["id_pk_i_b64"])
        cert_u_i = info["cert_u_i"]
        cert_a_i = info["cert_a_i"]

        costs = {}

        t0 = time.perf_counter()
        if not self._ca.verify_cert(cert_u_i):
            raise RuntimeError("Cert_U_I verification failed")
        costs["ML-DSA-65 verify Cert_U_I"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK Cert_U_I valid")

        t0 = time.perf_counter()
        if not self._ca.verify_cert(cert_a_i):
            raise RuntimeError("Cert_A_I verification failed")
        costs["ML-DSA-65 verify Cert_A_I"] = time.perf_counter() - t0
        if cert_a_i.get("subject") != aid_i:
            raise RuntimeError("Cert_A_I subject mismatch")
        print(f"[AGENT:{self.aid}] OK Cert_A_I valid")

        t0 = time.perf_counter()
        if not self._xmss.verify(canonical_json(m_0), sig_init, id_pk_i):
            raise RuntimeError("sigma^A_I_init verification failed")
        costs["XMSS verify sigma^A_I_init"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^A_I_init valid")

        # This is where the contact policy is enforced at the receiver, so the
        # provider's authorisation has to be verified, not merely present.
        t0 = time.perf_counter()
        self.verify_sig_ta_ac(sig_ta_ac, aid_i, id_pk_i)
        costs["XMSS verify sigma^TA_ac"] = time.perf_counter() - t0

        pk_u_i = pk_from_cert(cert_u_i)
        rcp = self.cp.get("rcp", {})
        chain_root = b64d(next_tok["image_b64"])
        tau_start = int(m_0["tau_start"])
        t0 = time.perf_counter()
        if not self._xmss.verify(
                build_tuple_message(chain_root, tau_start, q_ir, delta_ir),
                sig_u_cp, pk_u_i):
            raise RuntimeError("tok^msg+Time (ICP) verification failed")
        costs["XMSS verify tok^msg+Time (ICP)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK tok^msg+Time (ICP) valid")

        tau_now = int(time.time())
        if not tau_now - tau_start < delta_ir:
            raise RuntimeError(
                f"ICP time budget already elapsed: tau_now - tau_start = "
                f"{tau_now - tau_start}s >= Delta_IR = {delta_ir}s")
        print(f"[AGENT:{self.aid}] OK ICP time window valid "
              f"({tau_now - tau_start}s of {delta_ir}s elapsed)")

        image = b64d(next_tok["image_b64"])
        preimage = b64d(next_tok["preimage_b64"])
        t0 = time.perf_counter()
        if not verify_chain_element(preimage, q_ir - 1, q_ir,
                                    image, self.aid.encode()):
            raise RuntimeError("NextTok verification failed")
        costs["SHA-256 NextTok chain verify"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK NextTok valid, building m_1 ...")

        k_2 = create_key()
        t0 = time.perf_counter()
        k_sess = sha256(k_1 + k_2)
        costs["SHA-256 k_sess derivation"] = time.perf_counter() - t0

        if not any(c.get("peer_aid") == aid_i
                   for c in rcp.get("allowed_contacts", [])):
            raise RuntimeError(f"{aid_i} not in RCP allowed_contacts")
        q_ri = int(rcp["Q"])
        delta_ri = int(rcp["delta_sec"])

        t0 = time.perf_counter()
        seed_r = prf(k_2, self.aid, aid_i, 0)
        chain_r = personalized_hash_chain(seed_r, q_ri, aid_i.encode())
        costs[f"PRF seed + hash chain (n={q_ri})"] = time.perf_counter() - t0
        s_n = chain_r[q_ri]
        s_n_minus_1 = chain_r[q_ri - 1]
        print(f"[AGENT:{self.aid}] Receiver chain built "
              f"(n={q_ri}, root={s_n.hex()[:16]}...)")

        t0 = time.perf_counter()
        sig_u_r_cp, tau_start_r = self._user.user_sign_rcp(
            self.aid, s_n, q_ri, delta_ri)
        costs["XMSS sign tok^msg+Time (RCP)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK tok^msg+Time (RCP) signed "
              f"(tau'_start={tau_start_r})")

        res_1 = "handshake_ack"
        m_1 = {
            "k_2_b64": b64e(k_2),
            "res_1": res_1,
            "Q_ri": q_ri,
            "delta_ri": delta_ri,
            "tau_start_r": tau_start_r,
            "next_tok_r": {"image_b64": b64e(s_n),
                           "preimage_b64": b64e(s_n_minus_1)},
            "next_tok_i": {"preimage_b64": b64e(preimage)},
            "sig_u_r_cp_b64": b64e(sig_u_r_cp),
        }
        t0 = time.perf_counter()
        tag_1 = prf(k_sess, canonical_json(m_1))
        costs["HMAC-SHA256 tag_1 compute"] = time.perf_counter() - t0

        session.send({"type": "handshake_resp", "m_1": m_1,
                      "tag_1_b64": b64e(tag_1)})
        print(f"[AGENT:{self.aid}] OK Handshake response sent to {aid_i}")
        print_crypto_costs(f"Handshake Recv: {self.aid}", costs)

        delta_eff = min(delta_ir, delta_ri)
        session_expiry = tau_now + delta_eff
        print(f"[AGENT:{self.aid}] Session expiry = tau_now + "
              f"min({delta_ir}, {delta_ri}) = {delta_eff}s")

        self._session_state[aid_i] = {
            "role": "receiver",
            "remote_aid": aid_i,
            "tau_start": tau_start,
            "tau_start_r": tau_start_r,
            "k_1": k_1, "k_2": k_2, "k_sess": k_sess,
            "q_ir": q_ir, "delta_ir": delta_ir,
            "q_ri": q_ri, "delta_ri": delta_ri,
            "chain_r": chain_r,
            "last_s_released_idx": q_ri - 1,
            "last_rho_seen": preimage,
            "last_rho_seen_idx": q_ir - 1,
            "chain_i_root": chain_root,
            "ctr_rcp": q_ri - 1,
            "ctr_icp": q_ir - 1,
            "session_expiry": session_expiry,
            "round_num": 1,
        }
        chain_r[q_ri] = None

        return {
            "role": "receiver",
            "local_aid": self.aid,
            "remote_aid": aid_i,
            "k_sess": k_sess,
            "q_ir": q_ir,
            "delta_ir": delta_ir,
            "q_ri": q_ri,
            "delta_ri": delta_ri,
            "res_1": res_1,
            "session_expiry": session_expiry,
        }

    def send_data_request(self, session, req):
        """Send one request and block for the matched response."""
        aid_r = session.remote_aid
        state = self._session_state.get(aid_r)
        if state is None or state["role"] != "initiator":
            raise RuntimeError(f"No initiator state for {aid_r}")
        if state["ctr_icp"] <= 0:
            raise RuntimeError("ctr_ICP exhausted")
        if time.time() > state["session_expiry"]:
            raise RuntimeError("session expired")

        round_num = state["round_num"] + 1
        icp_idx = state["q_ir"] - round_num
        if icp_idx < 0:
            raise RuntimeError("initiator chain exhausted")

        rho_i = state["chain_i"][icp_idx]
        costs = {}
        m_i = {
            "round": round_num,
            "req": req,
            "next_tok_icp_b64": b64e(rho_i),
            "next_tok_rcp_b64": b64e(state["last_s_seen"]),
        }
        t0 = time.perf_counter()
        tag_i = prf(state["k_sess"], canonical_json(m_i))
        costs["HMAC-SHA256 tag compute"] = time.perf_counter() - t0

        print(f"\n[AGENT:{self.aid}] [REQUEST #{round_num}] "
              f"rho_{{{icp_idx}}} + echo s")
        print(f"   Message: {req.get('msg', '(no message)')[:200]}")
        session.send({"type": "data_request", "m": m_i, "tag_b64": b64e(tag_i)})

        state["chain_i"][icp_idx + 1] = None
        state["last_rho_released_idx"] = icp_idx
        state["ctr_icp"] -= 1

        if icp_idx == 0 and state.get("check_rho0_prf", True):
            if rho_i != prf(state["k_1"], self.aid, aid_r, 0):
                raise RuntimeError("rho_0 PRF check failed")

        print_crypto_costs(
            f"Data req #{round_num} outgoing (A_I): {self.aid}", costs)

        resp_msg = session.recv()
        if resp_msg is None:
            raise RuntimeError("connection closed before response")
        return self.handle_message(session, resp_msg)

    def _on_data_request(self, session, msg):
        """Receiver side: verify a request, answer it, release the next token."""
        aid_i = session.remote_aid
        state = self._session_state.get(aid_i)
        if state is None or state["role"] != "receiver":
            raise RuntimeError(f"No receiver state for {aid_i}")

        if state["ctr_rcp"] <= 0:
            session.send({"type": "error", "reason": "quota exhausted"})
            return {"error": "quota_exhausted"}
        if time.time() > state["session_expiry"]:
            session.send({"type": "error", "reason": "session expired"})
            return {"error": "session_expired"}

        costs = {}
        m = msg["m"]
        tag = b64d(msg["tag_b64"])
        t0 = time.perf_counter()
        if not prf_verify(state["k_sess"], canonical_json(m), tag):
            raise RuntimeError("data_request tag verification failed")
        costs["HMAC-SHA256 verify tag"] = time.perf_counter() - t0

        round_num = m["round"]
        if round_num != state["round_num"] + 1:
            raise RuntimeError(f"unexpected round {round_num} "
                               f"(expected {state['round_num'] + 1})")

        s_echo = b64d(m["next_tok_rcp_b64"])
        if s_echo != state["chain_r"][state["last_s_released_idx"]]:
            raise RuntimeError("NextTok^RCP echo mismatch")

        rho_new = b64d(m["next_tok_icp_b64"])
        icp_idx = state["q_ir"] - round_num
        t0 = time.perf_counter()
        if not verify_chain_step(rho_new, icp_idx + 1,
                                 self.aid.encode(), state["last_rho_seen"]):
            raise RuntimeError("NextTok^ICP chain-step verification failed")
        costs["SHA-256 ICP chain-step verify"] = time.perf_counter() - t0

        res = self._handle_app_request(m["req"])

        rcp_new_idx = state["q_ri"] - round_num
        if rcp_new_idx < 0:
            session.send({"type": "error", "reason": "receiver chain exhausted"})
            return {"error": "chain_exhausted"}
        s_new = state["chain_r"][rcp_new_idx]

        m_resp = {
            "round": round_num,
            "res": res,
            "next_tok_icp_b64": b64e(rho_new),
            "next_tok_rcp_b64": b64e(s_new),
        }
        t0 = time.perf_counter()
        tag_resp = prf(state["k_sess"], canonical_json(m_resp))
        costs["HMAC-SHA256 response tag compute"] = time.perf_counter() - t0

        preview = res.get("msg", "(no message)") if isinstance(res, dict) else str(res)
        print(f"\n[AGENT:{self.aid}] [RESPONSE #{round_num}] s_{{{rcp_new_idx}}}")
        print(f"   Response message: {preview[:200]}")

        session.send({"type": "data_response", "m": m_resp,
                      "tag_b64": b64e(tag_resp)})
        print_crypto_costs(f"Data round #{round_num} (A_R): {self.aid}", costs)

        state["chain_r"][rcp_new_idx + 1] = None
        state["last_rho_seen"] = rho_new
        state["last_rho_seen_idx"] = icp_idx
        state["last_s_released_idx"] = rcp_new_idx
        state["ctr_icp"] -= 1
        state["ctr_rcp"] -= 1
        state["round_num"] = round_num

        if (state["ctr_icp"] == 0 and icp_idx == 0
                and state.get("check_rho0_prf", True)):
            if rho_new != prf(state["k_1"], aid_i, self.aid, 0):
                raise RuntimeError("rho_0 PRF check failed")

        return {"round": round_num, "res": res}

    def _on_data_response(self, session, msg):
        """Initiator side: verify a response and advance both chain positions."""
        aid_r = session.remote_aid
        state = self._session_state.get(aid_r)
        if state is None or state["role"] != "initiator":
            raise RuntimeError(f"No initiator state for {aid_r}")

        if time.time() > state["session_expiry"]:
            raise RuntimeError("session expired (t_exp reached)")

        costs = {}
        m = msg["m"]
        tag = b64d(msg["tag_b64"])
        round_num = m["round"]
        res_data = m.get("res", {})
        preview = res_data.get("msg", "(no message)") if isinstance(res_data, dict) else str(res_data)
        print(f"\n[AGENT:{self.aid}] [RESPONSE RECEIVED] "
              f"Round #{round_num} from {aid_r}:")
        print(f"   Peer response: {preview[:200]}")

        t0 = time.perf_counter()
        if not prf_verify(state["k_sess"], canonical_json(m), tag):
            raise RuntimeError("data_response tag verification failed")
        costs["HMAC-SHA256 verify tag"] = time.perf_counter() - t0

        if round_num != state["round_num"] + 1:
            raise RuntimeError(f"unexpected response round {round_num}")

        icp_idx = state["q_ir"] - round_num
        if b64d(m["next_tok_icp_b64"]) != state["chain_i"][icp_idx]:
            raise RuntimeError("NextTok^ICP echo mismatch on response")

        s_new = b64d(m["next_tok_rcp_b64"])
        t0 = time.perf_counter()
        if not verify_chain_step(s_new, state["last_s_seen_idx"],
                                 self.aid.encode(), state["last_s_seen"]):
            raise RuntimeError("NextTok^RCP chain-step verification failed")
        costs["SHA-256 RCP chain-step verify"] = time.perf_counter() - t0

        state["last_s_seen"] = s_new
        state["last_s_seen_idx"] -= 1
        state["ctr_rcp"] -= 1
        state["round_num"] = round_num
        print(f"[AGENT:{self.aid}] OK response #{round_num} verified")
        print_crypto_costs(
            f"Data resp #{round_num} verify (A_I): {self.aid}", costs)

        if (state["ctr_rcp"] == 0 and state["last_s_seen_idx"] == 0
                and state.get("check_rho0_prf", True)):
            if s_new != prf(state["k_2"], aid_r, self.aid, 0):
                raise RuntimeError("s_0 PRF check failed")

        return m["res"]

    def terminate_A_session(self, session):
        """Close the session and scrub its crypto state from memory."""
        remote_aid = session.remote_aid
        bw_stats = session.bandwidth_stats()

        if bw_stats:
            data_phase = bw_stats.get("data")
            if data_phase:
                print_bandwidth_costs(
                    f"Data Transfer ({self.aid} <-> {remote_aid})",
                    {"data": data_phase},
                    src_label=self.aid, dst_label=remote_aid)
            print_bandwidth_costs(
                f"Agent2Agent Communication ({self.aid} <-> {remote_aid})",
                bw_stats, src_label=self.aid, dst_label=remote_aid)

        state = self._session_state.pop(remote_aid, None)
        if state:
            for key in ("k_1", "k_2", "k_sess"):
                if key in state:
                    state[key] = b"\x00" * len(state[key])
            for chain_key in ("chain_i", "chain_r"):
                chain = state.get(chain_key)
                if chain:
                    for i in range(len(chain)):
                        chain[i] = None
            state.clear()
        session.close()
        print(f"[AGENT:{self.aid}] OK A-session with {remote_aid} terminated, "
              f"state wiped")
        return bw_stats

    def run_receiver_loop(self, result):
        """Accept one incoming A-session and dispatch until the peer closes."""
        session = self.accept_session(timeout=30)
        if not session:
            return
        result["session"] = session
        while True:
            try:
                msg = session.recv()
            except Exception:
                break
            if msg is None:
                break
            out = self.handle_message(session, msg)
            if msg.get("type") == "handshake_init":
                result["handshake"] = out

    def attach_llm(self, model_client):
        if self.tool is None:
            print(f"[AGENT:{self.aid}] No tool configured, skipping LLM attach")
            return

        from agents_llm import AppAgent
        self._app_agent = AppAgent(
            name=self.aid,
            user_email=self.user_uid,
            tool_name=self.tool,
            model_client=model_client,
        )
        print(f"[AGENT:{self.aid}] OK LLM attached (tool={self.tool})")

    def close_llm(self):
        if self._app_agent is not None:
            self._app_agent.close()
            self._app_agent = None

    def _timed_llm_reply(self, prompt: str, label: str, task_stats=None) -> str:
        """Run one LLM call and record its latency."""
        t0 = time.perf_counter()
        reply = self._app_agent.reply(prompt)
        dt = time.perf_counter() - t0

        self._llm_total_calls += 1
        self._llm_total_sec += dt
        self._llm_by_label[label]["calls"] += 1
        self._llm_by_label[label]["sec"] += dt

        if task_stats is not None:
            task_stats["calls"] += 1
            task_stats["sec"] += dt
            task_stats["by_label"][label]["calls"] += 1
            task_stats["by_label"][label]["sec"] += dt

        print(f"[AGENT:{self.aid}] [LLM TIMING] {label}: "
              f"{dt * 1000:.2f} ms ({dt:.3f} s)")
        return reply

    def _print_llm_summary(self, title: str, stats: dict):
        print(f"\n[AGENT:{self.aid}] [LLM TOTAL] {title}: "
              f"calls={stats.get('calls', 0)} "
              f"total={stats.get('sec', 0.0) * 1000:.2f} ms")

    def _handle_app_request(self, req):
        """Receiver side: hand an incoming message to the LLM agent."""
        if self._app_agent is None or "msg" not in req:
            return {"status": "ok", "echo": req}

        from agents_llm import task_is_finished, TASK_FINISHED

        incoming = req["msg"]
        if task_is_finished(incoming):
            print(f"[AGENT:{self.aid}] [LLM] Peer sent TASK_FINISHED, "
                  f"echoing back")
            return {"msg": TASK_FINISHED}

        print(f"[AGENT:{self.aid}] [LLM] Handling peer message "
              f"({len(incoming)} chars)")
        reply = self._timed_llm_reply(incoming, "receiver reply")
        print(f"[AGENT:{self.aid}] [LLM] Reply generated ({len(reply)} chars)")
        return {"msg": reply}

    def run_llm_conversation(
            self,
            session,
            task: str,
            max_rounds: int = 10,
            min_peer_rounds_before_finish: int = 0,
            force_first_peer_request: bool = False,
            first_outgoing: str = "",
            auto_finish_after_first_peer_data: bool = False):
        if self._app_agent is None:
            raise RuntimeError(f"Agent {self.aid}: attach_llm() before running")

        from agents_llm import task_is_finished, TASK_FINISHED

        task_stats = {
            "calls": 0,
            "sec": 0.0,
            "by_label": defaultdict(lambda: {"calls": 0, "sec": 0.0}),
        }
        transcript = []

        def preview(text, limit=180):
            if not text:
                return "(empty)"
            one_line = " ".join(text.split())
            return one_line if len(one_line) <= limit else one_line[:limit] + "..."

        def finish(reason, rounds):
            self._print_llm_summary("task total", task_stats)
            return {"finished": True, "reason": reason, "rounds": rounds,
                    "transcript": transcript, "task_stats": task_stats}

        print(f"\n[AGENT:{self.aid}] === TASK INITIATED ===")
        print(f"\n[AGENT:{self.aid}] [TASK] {task}\n")

        if first_outgoing:
            outgoing = first_outgoing
        elif force_first_peer_request:
            outgoing = ("Please provide your own verified task data for this "
                        "step, using your tools and the current task context.")
        else:
            print(f"[AGENT:{self.aid}] [LLM] Generating initial response ...")
            outgoing = self._timed_llm_reply(
                f"Your task:\n{task}\n\n"
                "Generate the first concise message to the peer. "
                "Use only task-grounded facts and do not invent peer data.",
                "initiator initial", task_stats=task_stats)
        transcript.append({"role": "initiator", "msg": outgoing})
        print(f"[AGENT:{self.aid}] [OUTGOING] {preview(outgoing)}")

        peer_rounds = 0
        for i in range(max_rounds):
            if task_is_finished(outgoing):
                if peer_rounds < min_peer_rounds_before_finish:
                    print(f"[AGENT:{self.aid}] [GUARD] Ignoring premature "
                          f"{TASK_FINISHED}, peer rounds={peer_rounds}, "
                          f"required={min_peer_rounds_before_finish}")
                    outgoing = (
                        "Before we can finish, please provide your own verified "
                        "task data for this step from your tools. Use the current "
                        "task context and do not mark the task as complete yet.")
                    transcript.append({"role": "initiator", "msg": outgoing})
                    continue
                print(f"\n[AGENT:{self.aid}] [SUCCESS] Task finished after "
                      f"{i} rounds")
                return finish("initiator_emitted_task_finished", i)

            print(f"\n[AGENT:{self.aid}] [ROUND {i + 1}] Sending request ...")
            resp = self.send_data_request(session, {"msg": outgoing})
            incoming = resp.get("msg", "") if isinstance(resp, dict) else ""
            peer_rounds += 1
            transcript.append({"role": "receiver", "msg": incoming})
            print(f"[AGENT:{self.aid}] [RECEIVED] {preview(incoming)}")

            if task_is_finished(incoming):
                if peer_rounds < min_peer_rounds_before_finish:
                    print(f"[AGENT:{self.aid}] [GUARD] Peer emitted "
                          f"{TASK_FINISHED} before minimum peer rounds")
                    outgoing = (
                        "Please continue and share your verified task data for "
                        "this step before either side marks the task complete.")
                    transcript.append({"role": "initiator", "msg": outgoing})
                    continue
                print(f"\n[AGENT:{self.aid}] [SUCCESS] Task finished after "
                      f"{i + 1} rounds")
                return finish("receiver_emitted_task_finished", i + 1)

            if (auto_finish_after_first_peer_data
                    and peer_rounds >= min_peer_rounds_before_finish
                    and incoming.strip()):
                print(f"\n[AGENT:{self.aid}] [SUCCESS] Step data collected "
                      f"after {peer_rounds} peer round(s)")
                return finish("receiver_data_collected", i + 1)

            outgoing = self._timed_llm_reply(
                f"Task context:\n{task}\n\n"
                f"Peer message:\n{incoming}\n\n"
                "Reply as the orchestrator for this exact task. "
                "Use only verified carried context and explicit peer-provided data. "
                "If the outcome is complete, emit exactly <TASK_FINISHED>.",
                f"initiator round {i + 1} reply", task_stats=task_stats)
            transcript.append({"role": "initiator", "msg": outgoing})
            print(f"[AGENT:{self.aid}] [OUTGOING] {preview(outgoing)}")

        print(f"\n[AGENT:{self.aid}] [WARNING] max_rounds ({max_rounds}) "
              f"reached without {TASK_FINISHED}")
        self._print_llm_summary("task total", task_stats)
        return {"finished": False, "reason": "max_rounds_reached",
                "rounds": max_rounds, "transcript": transcript,
                "task_stats": task_stats}

    def _connect_to_agent(self, contact_info):
        """Open PQ-TLS to the peer and exchange application certificates."""
        aid_r = contact_info["aid_r"]
        host = contact_info["ed_r"]["ip"]
        port = int(contact_info["ed_r"]["port"])
        print(f"[AGENT:{self.aid}] Connecting to {aid_r} at {host}:{port} ...")

        ctx = make_client_context(self._tls_paths)
        tls_conn = open_tls_client(ctx, host, port,
                                   timeout=AGENT_SESSION_TIMEOUT_SEC)

        send_msg(tls_conn, {"type": "cert_exchange", "aid": self.aid,
                            "cert_a": self.cert_a})
        resp = recv_msg(tls_conn)
        if not resp or resp.get("type") == "reject":
            tls_conn.close()
            reason = resp.get("reason", "?") if resp else "no response"
            raise RuntimeError(f"Receiver rejected: {reason}")

        if not self._ca.verify_cert(resp["cert_a"]):
            send_msg(tls_conn, {"type": "reject", "reason": "cert invalid"})
            tls_conn.close()
            raise RuntimeError("Receiver cert verification failed")
        if resp["cert_a"].get("subject") != aid_r:
            send_msg(tls_conn, {"type": "reject", "reason": "subject mismatch"})
            tls_conn.close()
            raise RuntimeError("Cert subject mismatch")

        print(f"[AGENT:{self.aid}] OK Verified Cert_A of {aid_r}")
        send_msg(tls_conn, {"type": "verified"})
        return AgentSession(tls_conn, self.aid, aid_r, resp["cert_a"])

    def start_listener(self):
        if self._listener_running:
            return
        port = int(self.ed["port"])
        self._listener_ctx = make_server_context(self._tls_paths)
        self._listener_sock = make_listening_socket("127.0.0.1", port)
        self._listener_running = True
        self._listener_thread = threading.Thread(target=self._listen_loop,
                                                 daemon=True)
        self._listener_thread.start()
        print(f"[AGENT:{self.aid}] Listening on 127.0.0.1:{port}")

    def _listen_loop(self):
        while self._listener_running:
            try:
                conn, _ = self._listener_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls_conn = self._listener_ctx.wrap_socket(conn, server_side=True)
                session = self._handle_incoming(tls_conn)
                if session:
                    with self._pending_lock:
                        self._pending_sessions.append(session)
                    self._pending_event.set()
            except Exception as e:
                print(f"[AGENT:{self.aid}] Incoming error: {e}")

    def _handle_incoming(self, tls_conn):
        msg = recv_msg(tls_conn)
        if not msg or msg.get("type") != "cert_exchange":
            tls_conn.close()
            return None
        initiator_aid = msg["aid"]
        initiator_cert = msg["cert_a"]
        if not self._ca.verify_cert(initiator_cert):
            send_msg(tls_conn, {"type": "reject", "reason": "cert invalid"})
            tls_conn.close()
            return None
        if initiator_cert.get("subject") != initiator_aid:
            send_msg(tls_conn, {"type": "reject", "reason": "subject mismatch"})
            tls_conn.close()
            return None
        print(f"[AGENT:{self.aid}] OK Verified Cert_A of {initiator_aid}")
        send_msg(tls_conn, {"type": "cert_exchange", "aid": self.aid,
                            "cert_a": self.cert_a})
        ack = recv_msg(tls_conn)
        if not ack or ack.get("type") != "verified":
            tls_conn.close()
            return None
        print(f"[AGENT:{self.aid}] OK PQ-TLS session with {initiator_aid}")
        return AgentSession(tls_conn, self.aid, initiator_aid, initiator_cert)

    def accept_session(self, timeout=30):
        self._pending_event.wait(timeout=timeout)
        with self._pending_lock:
            if self._pending_sessions:
                session = self._pending_sessions.pop(0)
                if not self._pending_sessions:
                    self._pending_event.clear()
                return session
        return None

    def stop_listener(self):
        self._listener_running = False
        if self._listener_sock:
            self._listener_sock.close()
        if self._listener_thread:
            self._listener_thread.join(timeout=3)

    def initiate_contact(self, target_aid, xmss):
        """Ask the provider for authorisation to reach target_aid."""
        if self._tls is None:
            raise RuntimeError(f"Agent {self.aid}: call setup() first")
        costs = {}
        print(f"\n[AGENT:{self.aid}] === Contacting provider for {target_aid} ===")

        resp = self._tls.request({"action": "contact_request",
                                  "aid_i": self.aid, "aid_r": target_aid})
        bw = self._tls.pop_last_request_bandwidth()
        if bw:
            print_bandwidth_costs(
                f"Contact Request TLS payload: {self.aid} -> {target_aid}",
                {"contact_request": bw},
                src_label="agent", dst_label="provider")

        if not (resp and resp.get("success")):
            message = resp.get("message", "?") if resp else "no response"
            raise RuntimeError(f"Contact denied: {message}")
        print(f"[AGENT:{self.aid}] OK Provider granted access")

        t_exp = resp["t_exp"]
        cert_u_r = resp["cert_u_r"]
        aid_r = resp["aid_r"]
        ed_r = resp["ed_r"]
        cert_a_r = resp["cert_a_r"]
        id_pk_r = b64d(resp["id_pk_r_b64"])
        pk_r = b64d(resp["pk_r_b64"])
        sig_id_r = b64d(resp["sig_id_r_b64"])
        sig_a_r = b64d(resp["sig_a_r_b64"])
        aid_i = resp["aid_i"]
        id_pk_i = b64d(resp["id_pk_i_b64"])
        sig_ta_ac = b64d(resp["sig_ta_ac_b64"])

        t0 = time.perf_counter()
        if not self._ca.verify_cert(cert_u_r):
            raise RuntimeError("Cert_U_R verification failed")
        costs["ML-DSA-65 verify (Cert_U_R)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK Cert_U_R valid")
        pk_u_r = pk_from_cert(cert_u_r)

        ed_r_b = canonical_json(ed_r)
        t0 = time.perf_counter()
        if not xmss.verify(
                build_tuple_message(aid_r, ed_r_b, pk_r,
                                    self._user._provider_tls_pk,
                                    self._provider_id_pk),
                sig_a_r, pk_u_r):
            raise RuntimeError("sigma^U_R_A verification failed")
        costs["XMSS verify sigma^U_R_A"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U_R_A valid")

        t0 = time.perf_counter()
        if not xmss.verify(build_tuple_message(aid_r, id_pk_r),
                           sig_id_r, pk_u_r):
            raise RuntimeError("sigma^U_R_ID verification failed")
        costs["XMSS verify sigma^U_R_ID"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U_R_ID valid")

        t0 = time.perf_counter()
        if not xmss.verify(
                build_tuple_message(
                    t_exp, canonical_json(cert_u_r), aid_r,
                    ed_r_b, canonical_json(cert_a_r),
                    id_pk_r, pk_r, sig_id_r, sig_a_r, aid_i, id_pk_i),
                sig_ta_ac, self._provider_id_pk):
            raise RuntimeError("sigma^TA_ac verification failed")
        costs["XMSS verify sigma^TA_ac"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^TA_ac valid, all checks passed")

        print_crypto_costs(f"Contact: {self.aid} -> {target_aid}",
                           costs, resp.get("crypto_timing", {}),
                           local_label="Agent")

        contact_info = {
            "t_exp": t_exp, "aid_r": aid_r, "ed_r": ed_r,
            "cert_a_r": cert_a_r, "pk_r": pk_r, "id_pk_r": id_pk_r,
            "cert_u_r": cert_u_r, "pk_u_r": pk_u_r,
            "sig_ta_ac": sig_ta_ac,
        }
        self.contacts[aid_r] = contact_info
        print(f"[AGENT:{self.aid}] Stored contact: {aid_r}")
        return contact_info

    def request_signature(self, message):
        """All agent signing goes through the user, which holds the keys."""
        return self._user.agent_xmss_sign(self.aid, message)

    def ed_bytes(self):
        return canonical_json(self.ed)

    def cert_bytes(self):
        return canonical_json(self.cert_a)

    def save(self):
        cd = certs_dir("agents", self._safe)
        if self.cert_a:
            save_json(self.cert_a, f"{cd}/app_cert.json")
        if self.cp:
            save_json(self.cp, f"{cd}/policy.json")
        if self.sig_ta:
            save_json({
                "aid": self.aid,
                "sig_id_b64": b64e(self.sig_id) if self.sig_id else None,
                "sig_a_b64": b64e(self.sig_a) if self.sig_a else None,
                "sig_ta_b64": b64e(self.sig_ta) if self.sig_ta else None,
                "tls_pk_b64": b64e(self.tls_pk) if self.tls_pk else None,
                "id_pk_b64": b64e(self.id_pk) if self.id_pk else None,
            }, f"{cd}/registration.json")
