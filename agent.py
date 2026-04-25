"""
agent.py - Agent state, PQ-TLS connectivity, and A-session protocol.
"""

import socket
import threading
import time
from collections import defaultdict

from lib.common import (
    certs_dir, save_json, safe_name, build_tuple_message,
    create_key, prf, sha256,
    personalized_hash_chain, verify_chain_element,
    canonical_json, verify_chain_step, prf_verify, print_crypto_costs,
    print_bandwidth_costs,
)
from lib.crypto import pk_from_cert
from lib.tls_channel import (
    send_msg as _send,
    recv_msg as _recv,
    make_client_context,
    make_server_context,
    make_listening_socket,
    open_tls_client,
)
from lib.agent_session import AgentSession


AGENT_SESSION_TIMEOUT_SEC = 90


class Agent:

    def __init__(self, agent_data, policy):
        self.user_uid = agent_data["user_uid"]
        self.name     = agent_data["name"]
        self.aid      = f"{self.user_uid}:{self.name}"
        self.ed = {
            "device": agent_data["device"],
            "ip":     agent_data["ip"],
            "port":   agent_data["port"],
        }
        self.cp = policy
        self.tool = agent_data.get("tool")  # e.g. "calendar", "email", "writing"
        self._app_agent = None              # Agent (attached post-registration)

        self.tls_pk = None
        self.id_pk  = None
        self.cert_a = None
        self.sig_id = None
        self.sig_a  = None
        self.sig_ta = None

        self._tls          = None
        self._user         = None
        self._ca           = None
        self._provider_id_pk = None
        self._tls_paths    = None
        self._xmss         = None

        self._listener_sock    = None
        self._listener_thread  = None
        self._listener_running = False
        self._listener_ctx     = None
        self._pending_sessions = []
        self._pending_lock     = threading.Lock()
        self._pending_event    = threading.Event()

        self.contacts      = {}
        self._session_state = {}   # A-session crypto state
        self._safe         = safe_name(self.aid)

        # LLM timing aggregates 
        self._llm_total_calls = 0
        self._llm_total_sec = 0.0
        self._llm_by_label = defaultdict(lambda: {"calls": 0, "sec": 0.0})

    #  Post-registration setup 
    def setup(self, tls_client, user, ca, provider_id_pk, tls_paths):
        self._tls            = tls_client
        self._user           = user
        self._ca             = ca
        self._provider_id_pk = provider_id_pk
        self._tls_paths      = tls_paths
        self.start_listener()

    
    #  Unified message handler
    def handle_message(self, session, msg):
        """Route any message received over an agent-to-agent PQ-TLS session."""
        msg_type = msg.get("type")
        print(f"[AGENT:{self.aid}] handle_message: type={msg_type}")

        if   msg_type == "handshake_init":  
            return self._on_handshake_init(session, msg)
        elif msg_type == "handshake_resp":  
            return self._on_handshake_resp(session, msg)
        elif msg_type == "data_request":    
            return self._on_data_request(session, msg)
        elif msg_type == "data_response":   
            return self._on_data_response(session, msg)
        else:
            print(f"[AGENT:{self.aid}] Unknown message type: {msg_type}")
            return None

    
    #  A-Session entry point (initiator)
    def start_A_session(self, target_aid, xmss):
        """contact provider -> PQ-TLS -> send m_0 -> receive + verify m_1."""
        self._xmss = xmss
        contact_info = self.initiate_contact(target_aid, xmss)

        print(f"\n[AGENT:{self.aid}] === PQ-TLS to {target_aid} ===")
        session = self._connect_to_agent(contact_info)
        print(f"[AGENT:{self.aid}] OK PQ-TLS established")

        hs_state  = self._handshake_initiator(session, contact_info)
        resp_msg  = session.recv()
        if resp_msg is None:
            raise RuntimeError("handshake response not received")
        resp_state = self.handle_message(session, resp_msg)

        return {
            "session":        session,
            "role":           "initiator",
            "local_aid":      self.aid,
            "remote_aid":     contact_info["aid_r"],
            "k_sess":         resp_state["k_sess"],
            "q_ir":           hs_state["q_ir"],
            "delta_ir":       hs_state["delta_ir"],
            "q_ri":           resp_state["q_ri"],
            "delta_ri":       resp_state["delta_ri"],
            "res_1":          resp_state["res_1"],
            "session_expiry": resp_state["session_expiry"],
        }

    
    #  Handshake - initiator sends m_0
    def _handshake_initiator(self, session, contact_info):
        aid_r  = contact_info["aid_r"]
        t_exp  = contact_info["t_exp"]
        print(f"\n[AGENT:{self.aid}] === Handshake (initiator) ===")

        # Initiator budget comes from own ICP. In the 2-agent setting
        # there is a single A-session, so ICP == RCP values: Q_IR is the
        # chain length n' and delta_IR is the total time budget.
        icp = self.cp.get("icp", {})
        if not any(c.get("peer_aid") == aid_r
                   for c in icp.get("allowed_contacts", [])):
            raise RuntimeError(f"{aid_r} not in ICP allowed_contacts")
        q_ir     = int(icp["n_prime"])
        delta_ir = int(icp["delta_tot_sec"])

        costs = {}

        # k_1 + personalized chain  rho_0=PRF(k_1,aid_I,aid_R,0)
        k_1  = create_key()
        t0   = time.perf_counter()
        seed = prf(k_1, self.aid, aid_r, 0)
        chain = personalized_hash_chain(seed, q_ir, aid_r.encode())
        costs[f"PRF seed + hash chain (n'={q_ir})"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] Generated k_1 ({len(k_1)}B), "
              f"chain built (n'={q_ir}, root={chain[q_ir].hex()[:16]}...)")

        # sigma^U_CP = Sign(T_exp, aid_I, aid_R, rho_n', Q_IR, DELTA_IR)
        t0 = time.perf_counter()
        sig_u_cp = self._user.user_xmss_sign(
            build_tuple_message(t_exp, self.aid, aid_r,
                                chain[q_ir], q_ir, delta_ir))
        costs["XMSS sign sigma^U_CP"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U_CP signed")

        next_tok = {"image_hex":   chain[q_ir].hex(),
                    "preimage_hex": chain[q_ir - 1].hex()}

        info_ai = {
            "cert_u_i":  self._user.cert_u,
            "aid_i":     self.aid,
            "ed_i":      self.ed,
            "cert_a_i":  self.cert_a,
            "id_pk_i_hex": self.id_pk.hex(),
            "pk_i_hex":  self.tls_pk.hex(),
            "sig_id_hex": self.sig_id.hex(),
            "sig_a_hex": self.sig_a.hex(),
        }

        m_0 = {
            "k_1_hex":  k_1.hex(),
            "info_ai":  info_ai,
            "Q_ir":     q_ir,
            "delta_ir": delta_ir,
            "next_tok": next_tok,
        }

        t0 = time.perf_counter()
        sig_init = self.request_signature(canonical_json(m_0))
        costs["XMSS sign sigma^A_I_init"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^A_I_init signed")

        handshake_init = {
            "type":         "handshake_init",
            "m_0":          m_0,
            "sig_ta_ac_hex": contact_info["sig_ta_ac"].hex(),
            "sig_init_hex": sig_init.hex(),
            "sig_u_cp_hex": sig_u_cp.hex(),
        }
        session.send(handshake_init)
        print(f"[AGENT:{self.aid}] OK Handshake sent to {aid_r}")
        print_crypto_costs(f"Handshake Init: {self.aid}", costs)

        # Stash state so _on_handshake_resp can verify the reply
        self._session_state[aid_r] = {
            "role":    "initiator",
            "remote_aid": aid_r,
            "t_exp":   t_exp,
            "k_1":     k_1,
            "chain_i": chain,
            "q_ir":    q_ir,
            "delta_ir": delta_ir,
            "ctr_icp": q_ir - 1,
            "last_rho_released_idx": q_ir - 1,
            "pk_u_r":  contact_info["pk_u_r"],
            "session_expiry": time.time() + delta_ir,
            "round_num": 1,
        }

        return {"q_ir": q_ir, "delta_ir": delta_ir}

    
    #  Handshake - initiator verifies m_1   
    def _on_handshake_resp(self, session, msg):
        aid_r = session.remote_aid
        state = self._session_state.get(aid_r)
        if state is None or state["role"] != "initiator":
            raise RuntimeError(f"No initiator state for {aid_r}")

        costs  = {}
        m_1    = msg["m_1"]
        tag_1  = bytes.fromhex(msg["tag_1_hex"])
        k_2    = bytes.fromhex(m_1["k_2_hex"])

        t0 = time.perf_counter()
        k_sess = sha256(state["k_1"] + k_2)
        costs["SHA-256 k_sess derivation"] = time.perf_counter() - t0

        # Verify tag_1 over m_1
        t0 = time.perf_counter()
        if not prf_verify(k_sess, canonical_json(m_1), tag_1):
            raise RuntimeError("tag_1 verification failed")
        costs["HMAC-SHA256 verify tag_1"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK tag_1 valid")

        # NextTok^ICP_1 echo: receiver must echo rho_{n'-1}
        if bytes.fromhex(m_1["next_tok_i"]["preimage_hex"]) \
                != state["chain_i"][state["q_ir"] - 1]:
            raise RuntimeError("NextTok^ICP_1 echo mismatch")
        print(f"[AGENT:{self.aid}] OK NextTok^ICP_1 echo valid")

        # sigma^U_R_CP
        sig_u_r_cp = bytes.fromhex(m_1["sig_u_r_cp_hex"])
        s_n        = bytes.fromhex(m_1["next_tok_r"]["image_hex"])
        s_n_minus_1 = bytes.fromhex(m_1["next_tok_r"]["preimage_hex"])
        q_ri       = m_1["Q_ri"]
        delta_ri   = m_1["delta_ri"]
        t0 = time.perf_counter()
        if not self._xmss.verify(
                build_tuple_message(state["t_exp"], aid_r, self.aid,
                                    s_n, q_ri, delta_ri),
                sig_u_r_cp, state["pk_u_r"]):
            raise RuntimeError("sigma^U_R_CP verification failed")
        costs["XMSS verify sigma^U_R_CP"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U_R_CP valid")

        # Chain-step: s_n == H(s_{n-1} || n || aid_I)
        t0 = time.perf_counter()
        if not verify_chain_step(s_n_minus_1, q_ri,
                                 self.aid.encode(), s_n):
            raise RuntimeError("s_n chain-step verification failed")
        costs["SHA-256 chain-step verify (s_n)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK s_n chain-step valid")

        state.update({
            "k_2": k_2, "k_sess": k_sess,
            "q_ri": q_ri, "delta_ri": delta_ri,
            "chain_r_image": s_n,
            "last_s_seen": s_n_minus_1,
            "last_s_seen_idx": q_ri - 1,
            "ctr_rcp": q_ri - 1,
            "session_expiry": time.time() + delta_ri,
            "res_1": m_1["res_1"],
        })
        print(f"[AGENT:{self.aid}] OK Handshake response verified "
              f"(Q_RI={q_ri} DELTA_RI={delta_ri}s)")
        print_crypto_costs(f"Handshake Resp Verify: {self.aid}", costs)

        return {
            "k_sess":         k_sess,
            "q_ri":           q_ri,
            "delta_ri":       delta_ri,
            "res_1":          m_1["res_1"],
            "session_expiry": state["session_expiry"],
        }

    
    #  Handshake - receiver verifies m_0 and sends m_1
    def _on_handshake_init(self, session, msg):
        aid_i = session.remote_aid
        print(f"\n[AGENT:{self.aid}] === Handshake (receiver from {aid_i}) ===")

        m_0        = msg["m_0"]
        sig_ta_ac  = bytes.fromhex(msg["sig_ta_ac_hex"])
        sig_init   = bytes.fromhex(msg["sig_init_hex"])
        sig_u_cp   = bytes.fromhex(msg["sig_u_cp_hex"])

        info     = m_0["info_ai"]
        q_ir     = m_0["Q_ir"]
        delta_ir = m_0["delta_ir"]
        next_tok = m_0["next_tok"]
        k_1      = bytes.fromhex(m_0["k_1_hex"])
        id_pk_i  = bytes.fromhex(info["id_pk_i_hex"])
        cert_u_i = info["cert_u_i"]
        cert_a_i = info["cert_a_i"]

        costs = {}

        # Verify Cert_U_I
        print(f"[AGENT:{self.aid}] Verifying Cert_U_I ...")
        t0 = time.perf_counter()
        if not self._ca.verify_cert(cert_u_i):
            raise RuntimeError("Cert_U_I verification failed")
        costs["ML-DSA-65 verify Cert_U_I"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK Cert_U_I valid")

        # Verify Cert_A_I
        print(f"[AGENT:{self.aid}] Verifying Cert_A_I ...")
        t0 = time.perf_counter()
        if not self._ca.verify_cert(cert_a_i):
            raise RuntimeError("Cert_A_I verification failed")
        costs["ML-DSA-65 verify Cert_A_I"] = time.perf_counter() - t0
        if cert_a_i.get("subject") != aid_i:
            raise RuntimeError("Cert_A_I subject mismatch")
        print(f"[AGENT:{self.aid}] OK Cert_A_I valid")

        # Verify sigma^A_I_init over m_0
        print(f"[AGENT:{self.aid}] Verifying sigma^A_I_init ...")
        t0 = time.perf_counter()
        if not self._xmss.verify(canonical_json(m_0), sig_init, id_pk_i):
            raise RuntimeError("sigma^A_I_init verification failed")
        costs["XMSS verify sigma^A_I_init"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^A_I_init valid")

        # sigma^TA_ac (presence confirmed; full verify omitted here)
        print(f"[AGENT:{self.aid}] OK sigma^TA_ac present ({len(sig_ta_ac)}B)")

        # Verify sigma^U_CP — t_exp comes from THIS receiver's RCP
        # (the provider gave the initiator the same expiry, so the signed
        # message matches on both sides).
        print(f"[AGENT:{self.aid}] Verifying sigma^U_CP ...")
        pk_u_i     = pk_from_cert(cert_u_i)
        rcp        = self.cp.get("rcp", {})
        t_exp      = rcp.get("expiry", "2099-01-01T00:00:00Z")
        chain_root = bytes.fromhex(next_tok["image_hex"])
        t0 = time.perf_counter()
        if not self._xmss.verify(
                build_tuple_message(t_exp, aid_i, self.aid,
                                    chain_root, q_ir, delta_ir),
                sig_u_cp, pk_u_i):
            raise RuntimeError("sigma^U_CP verification failed")
        costs["XMSS verify sigma^U_CP"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U_CP valid")

        # Verify NextTok: preimage hashes to image
        print(f"[AGENT:{self.aid}] Verifying NextTok ...")
        image    = bytes.fromhex(next_tok["image_hex"])
        preimage = bytes.fromhex(next_tok["preimage_hex"])
        t0 = time.perf_counter()
        if not verify_chain_element(preimage, q_ir - 1, q_ir,
                                    image, self.aid.encode()):
            raise RuntimeError("NextTok verification failed")
        costs["SHA-256 NextTok chain verify"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK NextTok valid")
        print(f"[AGENT:{self.aid}] OK m_0 verified - building m_1 ...")

        #  Build m_1 
        k_2    = create_key()
        t0 = time.perf_counter()
        k_sess = sha256(k_1 + k_2)
        costs["SHA-256 k_sess derivation"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] Generated k_2 ({len(k_2)}B), k_sess derived")

        # Receiver budget comes from own RCP (per-A-session msg + time).
        if not any(c.get("peer_aid") == aid_i
                   for c in rcp.get("allowed_contacts", [])):
            raise RuntimeError(f"{aid_i} not in RCP allowed_contacts")
        q_ri     = int(rcp["Q"])
        delta_ri = int(rcp["delta_sec"])

        t0 = time.perf_counter()
        seed_r  = prf(k_2, self.aid, aid_i, 0)
        chain_r = personalized_hash_chain(seed_r, q_ri, aid_i.encode())
        costs[f"PRF seed + hash chain (n={q_ri})"] = time.perf_counter() - t0
        s_n       = chain_r[q_ri]
        s_n_minus_1 = chain_r[q_ri - 1]
        print(f"[AGENT:{self.aid}] Receiver chain built "
              f"(n={q_ri}, root={s_n.hex()[:16]}...)")

        t0 = time.perf_counter()
        sig_u_r_cp = self._user.user_xmss_sign(
            build_tuple_message(t_exp, self.aid, aid_i, s_n, q_ri, delta_ri))
        costs["XMSS sign sigma^U_R_CP"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U_R_CP signed")

        next_tok_i = {"preimage_hex": preimage.hex()}
        next_tok_r = {"image_hex":    s_n.hex(),
                      "preimage_hex": s_n_minus_1.hex()}

        res_1 = "handshake_ack"
        m_1   = {
            "k_2_hex":        k_2.hex(),
            "res_1":          res_1,
            "Q_ri":           q_ri,
            "delta_ri":       delta_ri,
            "next_tok_r":     next_tok_r,
            "next_tok_i":     next_tok_i,
            "sig_u_r_cp_hex": sig_u_r_cp.hex(),
        }
        t0 = time.perf_counter()
        tag_1 = prf(k_sess, canonical_json(m_1))
        costs["HMAC-SHA256 tag_1 compute"] = time.perf_counter() - t0

        handshake_resp = {
            "type":         "handshake_resp",
            "m_1":          m_1,
            "tag_1_hex":    tag_1.hex()
        }

        session.send(handshake_resp)
        print(f"[BANDWIDTH][AGENT:{self.aid}] <- Handshake response of size {len(canonical_json(handshake_resp))} sent to {aid_i}")
        print(f"[AGENT:{self.aid}] OK Handshake response sent to {aid_i}")
        print_crypto_costs(f"Handshake Recv: {self.aid}", costs)

        session_expiry = time.time() + delta_ir
        self._session_state[aid_i] = {
            "role": "receiver",
            "remote_aid": aid_i,
            "t_exp":   t_exp,
            "k_1": k_1, "k_2": k_2, "k_sess": k_sess,
            "q_ir": q_ir, "delta_ir": delta_ir,
            "q_ri": q_ri, "delta_ri": delta_ri,
            "chain_r": chain_r,
            "last_s_released_idx": q_ri - 1,
            "last_rho_seen":     preimage,
            "last_rho_seen_idx": q_ir - 1,
            "chain_i_root": chain_root,
            "ctr_rcp": q_ri - 1,
            "ctr_icp": q_ir - 1,
            "session_expiry": session_expiry,
            "round_num": 1,
        }
        chain_r[q_ri] = None   # drop s_n

        return {
            "role":           "receiver",
            "local_aid":      self.aid,
            "remote_aid":     aid_i,
            "k_sess":         k_sess,
            "q_ir":           q_ir,
            "delta_ir":       delta_ir,
            "q_ri":           q_ri,
            "delta_ri":       delta_ri,
            "res_1":          res_1,
            "session_expiry": session_expiry,
        }

    
    #  Data-transfer phase - initiator sends a request 
    def send_data_request(self, session, req):
        """Send one request and block for the matched response. Returns res."""
        aid_r = session.remote_aid
        state = self._session_state.get(aid_r)
        if state is None or state["role"] != "initiator":
            raise RuntimeError(f"No initiator state for {aid_r}")
        if state["ctr_icp"] <= 0:
            raise RuntimeError("ctr_ICP exhausted")
        if time.time() > state["session_expiry"]:
            raise RuntimeError("session expired")

        round_num = state["round_num"] + 1
        icp_idx   = state["q_ir"] - round_num
        if icp_idx < 0:
            raise RuntimeError("initiator chain exhausted")

        rho_i   = state["chain_i"][icp_idx]
        s_echo  = state["last_s_seen"]

        costs = {}
        m_i = {
            "round":           round_num,
            "req":             req,
            "next_tok_icp_hex": rho_i.hex(),
            "next_tok_rcp_hex": s_echo.hex(),
        }
        t0 = time.perf_counter()
        tag_i = prf(state["k_sess"], canonical_json(m_i))
        costs["HMAC-SHA256 tag compute"] = time.perf_counter() - t0
        print(f"\n[AGENT:{self.aid}] [REQUEST #{round_num}] Payload:")
        print(f"   Message: {req.get('msg', '(no message)')[:200]}")
        print(f"   ICP token index: rho_{{{icp_idx}}}")
        print(f"   RCP echo: s")
        print(f"[AGENT:{self.aid}] -> req #{round_num} (rho_{{{icp_idx}}}, echo s)")
        session.send({"type": "data_request", "m": m_i,
                      "tag_hex": tag_i.hex()})

        state["chain_i"][icp_idx + 1] = None   # drop rho_{n'-i+1}
        state["last_rho_released_idx"] = icp_idx
        state["ctr_icp"] -= 1

        if icp_idx == 0 and state.get("check_rho0_prf", True):
            expected_rho_0 = prf(state["k_1"], self.aid, aid_r, 0)
            if rho_i != expected_rho_0:
                raise RuntimeError("rho_0 PRF check failed")

        print_crypto_costs(f"Data req #{round_num} outgoing (A_I): {self.aid}", costs)

        resp_msg = session.recv()
        if resp_msg is None:
            raise RuntimeError("connection closed before response")
        return self.handle_message(session, resp_msg)

    
    #  Data-transfer phase - receiver handles a request 
    def _on_data_request(self, session, msg):
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
        m   = msg["m"]
        tag = bytes.fromhex(msg["tag_hex"])
        t0 = time.perf_counter()
        if not prf_verify(state["k_sess"], canonical_json(m), tag):
            raise RuntimeError("data_request tag verification failed")
        costs["HMAC-SHA256 verify tag"] = time.perf_counter() - t0

        round_num = m["round"]
        if round_num != state["round_num"] + 1:
            raise RuntimeError(f"unexpected round {round_num} "
                               f"(expected {state['round_num'] + 1})")

        # NextTok^RCP_i echo - must match what we last released
        s_echo = bytes.fromhex(m["next_tok_rcp_hex"])
        if s_echo != state["chain_r"][state["last_s_released_idx"]]:
            raise RuntimeError("NextTok^RCP echo mismatch")

        # NextTok^ICP_i chain-step: H(rho_{n'-i}, step, aid_R) == previous rho
        rho_new   = bytes.fromhex(m["next_tok_icp_hex"])
        icp_idx   = state["q_ir"] - round_num
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
            "round":           round_num,
            "res":             res,
            "next_tok_icp_hex": rho_new.hex(),
            "next_tok_rcp_hex": s_new.hex(),
        }
        t0 = time.perf_counter()
        tag_resp = prf(state["k_sess"], canonical_json(m_resp))
        costs["HMAC-SHA256 response tag compute"] = time.perf_counter() - t0
        
        print(f"\n[AGENT:{self.aid}] [RESPONSE #{round_num}] Payload:")
        resp_msg = res.get("msg", "(no message response)") if isinstance(res, dict) else str(res)
        print(f"   Response message: {resp_msg[:200]}")
        print(f"   RCP token index: s_{{{rcp_new_idx}}}")
        
        session.send({"type": "data_response", "m": m_resp,
                      "tag_hex": tag_resp.hex()})
        print(f"[AGENT:{self.aid}] <- req #{round_num} served "
              f"(rho echo, s_{{{rcp_new_idx}}})")
        print_crypto_costs(f"Data round #{round_num} (A_R): {self.aid}", costs)

        state["chain_r"][rcp_new_idx + 1] = None
        state["last_rho_seen"]     = rho_new
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

    
    #  Data-transfer phase - initiator verifies a response   
    def _on_data_response(self, session, msg):
        aid_r = session.remote_aid
        state = self._session_state.get(aid_r)
        if state is None or state["role"] != "initiator":
            raise RuntimeError(f"No initiator state for {aid_r}")

        costs = {}
        m   = msg["m"]
        tag = bytes.fromhex(msg["tag_hex"])
        
        # Show what was received before verification
        round_num = m["round"]
        res_data = m.get("res", {})
        res_msg = res_data.get("msg", "(no message)") if isinstance(res_data, dict) else str(res_data)
        print(f"\n[AGENT:{self.aid}] [RESPONSE RECEIVED] Round #{round_num} from {aid_r}:")
        print(f"   Peer response: {res_msg[:200]}")
        
        t0 = time.perf_counter()
        if not prf_verify(state["k_sess"], canonical_json(m), tag):
            raise RuntimeError("data_response tag verification failed")
        costs["HMAC-SHA256 verify tag"] = time.perf_counter() - t0

        if round_num != state["round_num"] + 1:
            raise RuntimeError(f"unexpected response round {round_num}")

        # NextTok^ICP echo == rho_{n'-i} we just sent
        icp_idx   = state["q_ir"] - round_num
        rho_echo  = bytes.fromhex(m["next_tok_icp_hex"])
        if rho_echo != state["chain_i"][icp_idx]:
            raise RuntimeError("NextTok^ICP echo mismatch on response")

        # NextTok^RCP chain-step: H(s_new, step, aid_I) == last s we saw
        s_new      = bytes.fromhex(m["next_tok_rcp_hex"])
        step_index = state["last_s_seen_idx"]
        t0 = time.perf_counter()
        if not verify_chain_step(s_new, step_index,
                                 self.aid.encode(), state["last_s_seen"]):
            raise RuntimeError("NextTok^RCP chain-step verification failed")
        costs["SHA-256 RCP chain-step verify"] = time.perf_counter() - t0

        state["last_s_seen"]     = s_new
        state["last_s_seen_idx"] -= 1
        state["ctr_rcp"]  -= 1
        state["round_num"] = round_num
        print(f"[AGENT:{self.aid}] OK response #{round_num} verified")
        print_crypto_costs(f"Data resp #{round_num} verify (A_I): {self.aid}", costs)

        if (state["ctr_rcp"] == 0 and state["last_s_seen_idx"] == 0
                and state.get("check_rho0_prf", True)):
            if s_new != prf(state["k_2"], aid_r, self.aid, 0):
                raise RuntimeError("s_0 PRF check failed")

        return m["res"]

    
    #  Session termination - wipe all A-session state    
    def terminate_A_session(self, session):
        """Close session and scrub all associated crypto state from memory."""
        remote_aid = session.remote_aid
        bw_stats = session.bandwidth_stats()

        if bw_stats:
            data_phase = bw_stats.get("data")
            if data_phase:
                print_bandwidth_costs(
                    f"Data Transfer ({self.aid} <-> {remote_aid})",
                    {"data": data_phase},
                    src_label=self.aid,
                    dst_label=remote_aid,
                )
            print_bandwidth_costs(
                f"Agent2Agent Communication ({self.aid} <-> {remote_aid})",
                bw_stats,
                src_label=self.aid,
                dst_label=remote_aid,
            )

        state = self._session_state.pop(remote_aid, None)
        if state:
            for key in ("k_1", "k_2", "k_sess"):
                if key in state:
                    state[key] = b"\x00" * len(state[key])
            chain_i = state.get("chain_i")
            if chain_i:
                for i in range(len(chain_i)):
                    chain_i[i] = None
            chain_r = state.get("chain_r")
            if chain_r:
                for i in range(len(chain_r)):
                    chain_r[i] = None
            state.clear()
        session.close()
        print(f"[AGENT:{self.aid}] OK A-session with {remote_aid} terminated, state wiped")
        return bw_stats

    def run_receiver_loop(self, result):
        """Accept one incoming A-session and keep dispatching messages to
        handle_message() until the peer closes. Populates `result` with
        `session` (once accepted) and `handshake` (after handshake_init).

        Designed to run in a background thread while the initiator drives
        the session. Used by both the two-agent receiver (e.g. Alice in
        Phase A) and every MA receiver.
        """
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

    def close_llm(self):
        if self._app_agent is not None:
            self._app_agent.close()
            self._app_agent = None

    
    #  LLM attachment  
    def attach_llm(self, model_client):
        """Bind an AutoGen-backed AppAgent to this agent using this agent's tool."""
        if self.tool is None:
            print(f"[AGENT:{self.aid}] No tool configured - skipping LLM attach")
            return
        from agents_llm import AppAgent
        self._app_agent = AppAgent(
            name=self.aid,
            user_email=self.user_uid,
            tool_name=self.tool,
            model_client=model_client,
        )
        print(f"[AGENT:{self.aid}] OK LLM attached (tool={self.tool})")

    
    #  LLM timing handler  
    def _timed_llm_reply(self, prompt: str, label: str, task_stats=None) -> str:
        """Run one LLM call and print wall-clock latency."""
        t0 = time.perf_counter()
        reply = self._app_agent.reply(prompt)
        dt = time.perf_counter() - t0

        # Global per-agent accumulators.
        self._llm_total_calls += 1
        self._llm_total_sec += dt
        label_stats = self._llm_by_label[label]
        label_stats["calls"] += 1
        label_stats["sec"] += dt

        # Optional per-task accumulator.
        if task_stats is not None:
            task_stats["calls"] += 1
            task_stats["sec"] += dt
            t_label_stats = task_stats["by_label"][label]
            t_label_stats["calls"] += 1
            t_label_stats["sec"] += dt

        print(f"[AGENT:{self.aid}] [LLM TIMING] {label}: {dt*1000:.2f} ms ({dt:.3f} s)")
        return reply

    def _print_llm_summary(self, title: str, stats: dict):
        """Print a minimal aggregated LLM timing summary."""
        calls = stats.get("calls", 0)
        total_sec = stats.get("sec", 0.0)
        total_ms = total_sec * 1000.0

        print(f"\n[AGENT:{self.aid}] [LLM TOTAL] {title}: "
              f"calls={calls} total={total_ms:.2f} ms")

    def _handle_app_request(self, req):
        """Receiver dispatches incoming message to its LLM agent."""
        if self._app_agent is None or "msg" not in req:
            return {"status": "ok", "echo": req}

        incoming_msg = req["msg"]

        from agents_llm import task_is_finished, TASK_FINISHED
        if task_is_finished(incoming_msg):
            print(f"[AGENT:{self.aid}] [LLM] Peer sent TASK_FINISHED — echoing back")
            return {"msg": TASK_FINISHED}

        print(f"[AGENT:{self.aid}] [LLM] Handling peer message "
              f"({len(incoming_msg)} chars)")

        reply = self._timed_llm_reply(incoming_msg, "receiver reply")

        print(f"[AGENT:{self.aid}] [LLM] Reply generated "
              f"({len(reply)} chars)")

        return {"msg": reply}

    
    #  Data-transfer driver - initiator side (LLM conversation loop)    
    def run_llm_conversation(
            self,
            session,
            task: str,
            max_rounds: int = 10,
            min_peer_rounds_before_finish: int = 0,
            force_first_peer_request: bool = False,
            first_outgoing: str = "",
            auto_finish_after_first_peer_data: bool = False):
        """Drive an LLM-to-LLM conversation until TASK_FINISHED or max_rounds."""
        if self._app_agent is None:
            raise RuntimeError(f"Agent {self.aid}: attach_llm() before running")

        from agents_llm import task_is_finished, TASK_FINISHED

        task_stats = {
            "calls": 0,
            "sec": 0.0,
            "by_label": defaultdict(lambda: {"calls": 0, "sec": 0.0}),
        }
        transcript = []

        def _preview(text, limit=180):
            if not text:
                return "(empty)"
            one_line = " ".join(text.split())
            if len(one_line) <= limit:
                return one_line
            return one_line[:limit] + "..."

        print(f"\n[AGENT:{self.aid}] +=======================================+")
        print(f"[AGENT:{self.aid}] |         === TASK INITIATED ===        |")
        print(f"[AGENT:{self.aid}] +=======================================+")
        print(f"\n[AGENT:{self.aid}] [TASK] Task Description:")
        print(f"{task}\n")

        if first_outgoing:
            print(f"[AGENT:{self.aid}] [LLM] Using caller-provided first peer request...")
            outgoing = first_outgoing
        elif force_first_peer_request:
            print(f"[AGENT:{self.aid}] [LLM] Using deterministic first peer request...")
            outgoing = (
                "Please provide your own verified task data for this step, "
                "using your tools and the current task context."
            )
        else:
            print(f"[AGENT:{self.aid}] [LLM] Generating initial response...")
            outgoing = self._timed_llm_reply(
                (
                    f"Your task:\n{task}\n\n"
                    "Generate the first concise message to the peer. "
                    "Use only task-grounded facts and do not invent peer data."
                ),
                "initiator initial",
                task_stats=task_stats,
            )
        transcript.append({"role": "initiator", "msg": outgoing})
        print(f"[AGENT:{self.aid}] [OUTGOING] Initial message preview: "
              f"{_preview(outgoing)}")

        peer_rounds = 0
        for i in range(max_rounds):
            if task_is_finished(outgoing):
                if peer_rounds < min_peer_rounds_before_finish:
                    print(
                        f"[AGENT:{self.aid}] [GUARD] Ignoring premature "
                        f"{TASK_FINISHED}; peer rounds={peer_rounds}, "
                        f"required={min_peer_rounds_before_finish}")
                    outgoing = (
                        "Before we can finish, please provide your own verified "
                        "task data for this step from your tools. Use the current "
                        "task context and do not mark the task as complete yet."
                    )
                    transcript.append({"role": "initiator", "msg": outgoing})
                    print(f"[AGENT:{self.aid}] [OUTGOING] Guard rewrite preview: "
                          f"{_preview(outgoing)}")
                    continue
                print(f"\n[AGENT:{self.aid}] [SUCCESS] Task finished after {i} rounds")
                self._print_llm_summary("task total", task_stats)
                return {
                    "finished": True,
                    "reason": "initiator_emitted_task_finished",
                    "rounds": i,
                    "transcript": transcript,
                    "task_stats": task_stats,
                }

            print(f"\n[AGENT:{self.aid}] [ROUND {i+1}] Sending request and waiting for response...")
            resp = self.send_data_request(session, {"msg": outgoing})
            incoming = resp.get("msg", "") if isinstance(resp, dict) else ""
            peer_rounds += 1
            transcript.append({"role": "receiver", "msg": incoming})

            print(f"[AGENT:{self.aid}] [RECEIVED] Round {i+1} preview: "
                  f"{_preview(incoming)}")

            if task_is_finished(incoming):
                if peer_rounds < min_peer_rounds_before_finish:
                    print(
                        f"[AGENT:{self.aid}] [GUARD] Peer emitted {TASK_FINISHED} "
                        f"before minimum peer rounds were met")
                    outgoing = (
                        "Please continue and share your verified task data for this "
                        "step before either side marks the task as complete."
                    )
                    transcript.append({"role": "initiator", "msg": outgoing})
                    print(f"[AGENT:{self.aid}] [OUTGOING] Guard continue preview: "
                          f"{_preview(outgoing)}")
                    continue
                print(f"\n[AGENT:{self.aid}] [SUCCESS] Task finished after {i + 1} rounds")
                self._print_llm_summary("task total", task_stats)
                return {
                    "finished": True,
                    "reason": "receiver_emitted_task_finished",
                    "rounds": i + 1,
                    "transcript": transcript,
                    "task_stats": task_stats,
                }

            if (auto_finish_after_first_peer_data
                    and peer_rounds >= min_peer_rounds_before_finish
                    and incoming.strip()):
                print(
                    f"\n[AGENT:{self.aid}] [SUCCESS] Step data collected after "
                    f"{peer_rounds} peer round(s)")
                self._print_llm_summary("task total", task_stats)
                return {
                    "finished": True,
                    "reason": "receiver_data_collected",
                    "rounds": i + 1,
                    "transcript": transcript,
                    "task_stats": task_stats,
                }

            print(f"\n[AGENT:{self.aid}] [LLM] Processing peer response and generating reply...")
            outgoing = self._timed_llm_reply(
                (
                    f"Task context:\n{task}\n\n"
                    f"Peer message:\n{incoming}\n\n"
                    "Reply as the orchestrator for this exact task. "
                    "Use only verified carried context and explicit peer-provided data. "
                    "If the outcome is complete, emit exactly <TASK_FINISHED>."
                ),
                f"initiator round {i+1} reply",
                task_stats=task_stats,
            )
            transcript.append({"role": "initiator", "msg": outgoing})
            print(f"[AGENT:{self.aid}] [OUTGOING] Round {i+1} preview: "
                  f"{_preview(outgoing)}")

        print(f"\n[AGENT:{self.aid}] [WARNING] max_rounds ({max_rounds}) reached without {TASK_FINISHED}")
        self._print_llm_summary("task total", task_stats)
        return {
            "finished": False,
            "reason": "max_rounds_reached",
            "rounds": max_rounds,
            "transcript": transcript,
            "task_stats": task_stats,
        }

    
    #  PQ-TLS to another agent (initiator side)    
    def _connect_to_agent(self, contact_info):
        aid_r = contact_info["aid_r"]
        host  = contact_info["ed_r"]["ip"]
        port  = int(contact_info["ed_r"]["port"])
        print(f"[AGENT:{self.aid}] Connecting to {aid_r} at {host}:{port} ...")

        ctx      = make_client_context(self._tls_paths)
        tls_conn = open_tls_client(ctx, host, port,
                       timeout=AGENT_SESSION_TIMEOUT_SEC)

        _send(tls_conn, {"type": "cert_exchange", "aid": self.aid,
                          "cert_a": self.cert_a})
        resp = _recv(tls_conn)
        if not resp or resp.get("type") == "reject":
            tls_conn.close()
            raise RuntimeError(
                f"Receiver rejected: "
                f"{resp.get('reason', '?') if resp else 'no response'}")

        if not self._ca.verify_cert(resp["cert_a"]):
            _send(tls_conn, {"type": "reject", "reason": "cert invalid"})
            tls_conn.close()
            raise RuntimeError("Receiver cert verification failed")
        if resp["cert_a"].get("subject") != aid_r:
            _send(tls_conn, {"type": "reject", "reason": "subject mismatch"})
            tls_conn.close()
            raise RuntimeError("Cert subject mismatch")

        print(f"[AGENT:{self.aid}] OK Verified Cert_A of {aid_r}")
        _send(tls_conn, {"type": "verified"})
        return AgentSession(tls_conn, self.aid, aid_r, resp["cert_a"])

    
    #  PQ-TLS listener (receiver side)    
    def start_listener(self):
        if self._listener_running:
            return
        port = int(self.ed["port"])
        self._listener_ctx  = make_server_context(self._tls_paths)
        self._listener_sock = make_listening_socket("127.0.0.1", port)
        self._listener_running = True
        self._listener_thread  = threading.Thread(
            target=self._listen_loop, daemon=True)
        self._listener_thread.start()
        print(f"[AGENT:{self.aid}] Listening on 127.0.0.1:{port}")

    def _listen_loop(self):
        while self._listener_running:
            try:
                conn, addr = self._listener_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls_conn = self._listener_ctx.wrap_socket(conn, server_side=True)
                session  = self._handle_incoming(tls_conn)
                if session:
                    with self._pending_lock:
                        self._pending_sessions.append(session)
                    self._pending_event.set()
            except Exception as e:
                print(f"[AGENT:{self.aid}] Incoming error: {e}")

    def _handle_incoming(self, tls_conn):
        msg = _recv(tls_conn)
        if not msg or msg.get("type") != "cert_exchange":
            tls_conn.close()
            return None
        initiator_aid  = msg["aid"]
        initiator_cert = msg["cert_a"]
        if not self._ca.verify_cert(initiator_cert):
            _send(tls_conn, {"type": "reject", "reason": "cert invalid"})
            tls_conn.close()
            return None
        if initiator_cert.get("subject") != initiator_aid:
            _send(tls_conn, {"type": "reject", "reason": "subject mismatch"})
            tls_conn.close()
            return None
        print(f"[AGENT:{self.aid}] OK Verified Cert_A of {initiator_aid}")
        _send(tls_conn, {"type": "cert_exchange", "aid": self.aid,
                          "cert_a": self.cert_a})
        ack = _recv(tls_conn)
        if not ack or ack.get("type") != "verified":
            tls_conn.close()
            return None
        print(f"[AGENT:{self.aid}] OK PQ-TLS session with {initiator_aid}")
        return AgentSession(tls_conn, self.aid, initiator_aid, initiator_cert)

    def accept_session(self, timeout=30):
        self._pending_event.wait(timeout=timeout)
        with self._pending_lock:
            if self._pending_sessions:
                s = self._pending_sessions.pop(0)
                if not self._pending_sessions:
                    self._pending_event.clear()
                return s
        return None

    def stop_listener(self):
        self._listener_running = False
        if self._listener_sock:
            self._listener_sock.close()
        if self._listener_thread:
            self._listener_thread.join(timeout=3)

    
    #  Contacting the Provider    
    def initiate_contact(self, target_aid, xmss):
        if self._tls is None:
            raise RuntimeError(f"Agent {self.aid}: call setup() first")
        costs = {}
        print(f"\n[AGENT:{self.aid}] === Contacting provider for {target_aid} ===")

        resp = self._tls.request({
            "action": "contact_request",
            "aid_i": self.aid, "aid_r": target_aid,
        })
        bw = self._tls.pop_last_request_bandwidth()
        if bw:
            print_bandwidth_costs(
                f"Contact Request TLS payload: {self.aid} -> {target_aid}",
                {"contact_request": bw},
                src_label="agent",
                dst_label="provider",
            )

        if not (resp and resp.get("success")):
            raise RuntimeError(
                f"Contact denied: {resp.get('message', '?') if resp else 'no response'}")
        print(f"[AGENT:{self.aid}] OK Provider granted access")

        t_exp     = resp["t_exp"]
        cert_u_r  = resp["cert_u_r"]
        aid_r     = resp["aid_r"]
        ed_r      = resp["ed_r"]
        cert_a_r  = resp["cert_a_r"]
        id_pk_r   = bytes.fromhex(resp["id_pk_r_hex"])
        pk_r      = bytes.fromhex(resp["pk_r_hex"])
        sig_id_r  = bytes.fromhex(resp["sig_id_r_hex"])
        sig_a_r   = bytes.fromhex(resp["sig_a_r_hex"])
        aid_i     = resp["aid_i"]
        id_pk_i   = bytes.fromhex(resp["id_pk_i_hex"])
        sig_ta_ac = bytes.fromhex(resp["sig_ta_ac_hex"])

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
        print(f"[AGENT:{self.aid}] OK sigma^TA_ac valid - all passed")

        print_crypto_costs(
            f"Contact: {self.aid} -> {target_aid}",
            costs, resp.get("crypto_timing", {}), local_label="Agent")

        contact_info = {
            "t_exp": t_exp, "aid_r": aid_r, "ed_r": ed_r,
            "cert_a_r": cert_a_r, "pk_r": pk_r, "id_pk_r": id_pk_r,
            "cert_u_r": cert_u_r, "pk_u_r": pk_u_r,
            "sig_ta_ac": sig_ta_ac,
        }
        self.store_contact(contact_info)
        return contact_info

    def store_contact(self, ci):
        self.contacts[ci["aid_r"]] = ci
        print(f"[AGENT:{self.aid}] Stored contact: {ci['aid_r']}")

    #  Key operations (delegated to User) 
    def request_signature(self, message):
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
                "aid":        self.aid,
                "sig_id_hex": self.sig_id.hex() if self.sig_id else None,
                "sig_a_hex":  self.sig_a.hex()  if self.sig_a  else None,
                "sig_ta_hex": self.sig_ta.hex() if self.sig_ta else None,
                "tls_pk_hex": self.tls_pk.hex() if self.tls_pk else None,
                "id_pk_hex":  self.id_pk.hex()  if self.id_pk  else None,
            }, f"{cd}/registration.json")
