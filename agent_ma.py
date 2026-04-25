"""
agent_ma.py - Multi-agent extension of Agent for Magiq.

"""

import threading
import time
import re
import os

from lib.common import (
    ROOT_DIR,
    build_tuple_message, create_key, prf, sha256, canonical_json,
    personalized_hash_chain, verify_chain_element,
    build_merkle_tree, get_merkle_proof, verify_merkle_proof,
    print_crypto_costs,
)
from lib.crypto import pk_from_cert
from lib.metrics import banner

from agent import Agent


class AgentMA(Agent):
    """Agent with the C-session enabled."""

    def __init__(self, agent_data, policy):
        super().__init__(agent_data, policy)
        self._task_state = None   # orchestrator-side ICP state; None between tasks

    
    #  User-Agent Interaction subprotocol 
    
    def run_user_agent_interaction(self, task, workflow, xmss):
        """ orchestrator agent generates m hash chains, gets the user's signature
        on the Merkle root, and stores the tree + signature for later use.

        Args:
            task:     high-level task description (unsigned context only).
            workflow: list[dict] with keys {"agent_aid","instruction"};
                      order defines which receivers are contacted.
            xmss:     XMSS wrapper .
        """
        self._xmss = xmss
        if not workflow:
            raise RuntimeError("workflow is empty")

        icp = self.cp.get("icp", {})
        if not icp:
            raise RuntimeError(f"Agent {self.aid}: no ICP in policy")

        n_prime   = int(icp["n_prime"])
        delta_tot = int(icp["delta_tot_sec"])
        t_agents  = len(workflow)
        m         = int(icp.get("m", t_agents))
        if m < t_agents:
            raise RuntimeError(f"ICP m ({m}) < t ({t_agents}); "
                               "at least one chain per agent required")

        # Chain->agent assignment: first t cover each agent once
        agent_list  = [w["agent_aid"] for w in workflow]
        assignments = list(agent_list) + [
            agent_list[i % t_agents] for i in range(m - t_agents)]

        sid  = create_key(16)
        addr = f"{self.ed['ip']}:{self.ed['port']}"

        costs = {}
        print(f"\n[AGENT:{self.aid}] === (i) User-Agent Interaction ===")
        print(f"[AGENT:{self.aid}] Workflow: "
              + ", ".join(f"{i+1}.{w['agent_aid']}"
                          for i, w in enumerate(workflow)))
        print(f"[AGENT:{self.aid}] ICP: m={m}, n'={n_prime}, "
              f"Delta_tot={delta_tot}s (Q_tot={m * n_prime})")

        # Build m personalized hash chains.
        t0 = time.perf_counter()
        chains = []
        for i, aid_j in enumerate(assignments):
            seed  = prf(sid, self.aid, aid_j, f"{addr}:{i}")
            chain = personalized_hash_chain(seed, n_prime, aid_j.encode())
            chains.append({"agent_aid": aid_j, "seed": seed, "chain": chain})
        costs[f"PRF seeds + {m} hash chains (n'={n_prime})"] = \
            time.perf_counter() - t0

        # Merkle tree over the m chain roots {rho^i_{n'}}.
        t0 = time.perf_counter()
        leaves = [c["chain"][n_prime] for c in chains]
        m_root, m_levels = build_merkle_tree(leaves)
        costs[f"Merkle tree over {m} leaves"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] Mroot={m_root.hex()[:16]}...  "
              f"({len(m_levels)} levels)")

        # Step 4 — user signs sigma^U*_ICP over <T_exp,A*_I,Mroot,Delta_tot>.
        t0 = time.perf_counter()
        sig_u_icp, t_exp = self._user.user_sign_icp(self.aid, m_root, delta_tot)
        costs["XMSS sign sigma^U*_ICP"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U*_ICP signed (T_exp={t_exp})")

        #  Orchestrator verifies the returned signature.
        t0 = time.perf_counter()
        if not xmss.verify(
                build_tuple_message(str(t_exp), self.aid, m_root,
                                     str(delta_tot)),
                sig_u_icp, self._user.id_pk):
            raise RuntimeError("sigma^U*_ICP self-verification failed")
        costs["XMSS verify sigma^U*_ICP"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U*_ICP verified; "
              f"Merkle tree stored")

        self._task_state = {
            "task":       task,
            "workflow":   workflow,
            "n_prime":    n_prime,
            "m":          m,
            "delta_tot":  delta_tot,
            "sid":        sid,
            "addr":       addr,
            "chains":     chains,
            "m_root":     m_root,
            "m_levels":   m_levels,
            "sig_u_icp":  sig_u_icp,
            "t_exp":      t_exp,
            "t_start":    time.time(),
            "chain_next": {},   # count of chains for that aid used
        }

        print_crypto_costs(f"User-Agent Interaction: {self.aid}", costs)
        return self._task_state

    def reset_task_state(self):
        """Scrub ICP state between tasks."""
        if self._task_state is None:
            return
        for c in self._task_state.get("chains", []):
            ch = c.get("chain")
            if ch:
                for i in range(len(ch)):
                    ch[i] = None
            seed = c.get("seed")
            if seed:
                c["seed"] = b"\x00" * len(seed)
        self._task_state = None

    def cleanup_task(self, receivers):
        """Comprehensive post-task cleanup for the multi-agent setting.

        Guarantees (so it can safely live inside a finally): every orchestrator
        + receiver A-session key / chain is wiped, all LLM histories are
        reset, and the ICP Merkle tree + per-agent chains are scrubbed.
        Call this once per MA task.
        """
        # Wipe any session state that slipped past terminate_A_session
        for agent in (self, *receivers.values()):
            remaining = list(agent._session_state.keys())
            if not remaining:
                continue
            for remote_aid in remaining:
                state = agent._session_state.pop(remote_aid, {})
                for key in ("k_1", "k_2", "k_sess"):
                    v = state.get(key)
                    if v:
                        state[key] = b"\x00" * len(v)
                for chain_key in ("chain_i", "chain_r"):
                    ch = state.get(chain_key)
                    if ch:
                        for i in range(len(ch)):
                            ch[i] = None
                state.clear()
            print(f"[AGENT:{agent.aid}] Wiped {len(remaining)} "
                  f"leftover A-session state(s)")

        for ag in (self, *receivers.values()):
            if ag._app_agent:
                ag._app_agent.reset()
            ag._llm_total_calls = 0
            ag._llm_total_sec   = 0.0
            ag._llm_by_label.clear()

        self.reset_task_state()

    
    #  Handshake (initiator) — uses pre-generated chain + Merkle proof
    
    def _handshake_initiator(self, session, contact_info):
        aid_r = contact_info["aid_r"]
        t_exp = contact_info["t_exp"]
        print(f"\n[AGENT:{self.aid}] === Handshake (initiator, MA) ===")

        tstate = self._task_state
        if tstate is None:
            raise RuntimeError(
                f"Agent {self.aid}: run_user_agent_interaction() must be "
                "called before start_A_session() in the multi-agent protocol")

        # ICP Delta_tot check.
        if time.time() > tstate["t_start"] + tstate["delta_tot"]:
            raise RuntimeError("ICP Delta_tot expired — task deadline passed")

        matching = [i for i, c in enumerate(tstate["chains"])
                    if c["agent_aid"] == aid_r]
        if not matching:
            raise RuntimeError(f"No pre-generated chain for {aid_r} in ICP")
        used = tstate["chain_next"].get(aid_r, 0)
        if used >= len(matching):
            raise RuntimeError(f"All ICP chains for {aid_r} consumed")
        leaf_index = matching[used]
        tstate["chain_next"][aid_r] = used + 1

        chain_entry = tstate["chains"][leaf_index]
        chain       = chain_entry["chain"]
        n_prime     = tstate["n_prime"]

        # Peer must be in orchestrator's ICP.allowed_contacts.
        icp = self.cp.get("icp", {})
        if not any(c.get("peer_aid") == aid_r
                   for c in icp.get("allowed_contacts", [])):
            raise RuntimeError(f"{aid_r} not in ICP allowed_contacts")
        q_ir     = n_prime
        delta_ir = int(tstate["delta_tot"])

        costs = {}

        t0 = time.perf_counter()
        merkle_proof = get_merkle_proof(tstate["m_levels"], leaf_index)
        costs["Merkle proof fetch"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] ICP chain #{leaf_index} -> {aid_r} "
              f"(root={chain[n_prime].hex()[:16]}..., depth="
              f"{len(merkle_proof)})")

        # A-session key (fresh k_1 per session).
        k_1 = create_key()

        next_tok = {"image_hex":   chain[n_prime].hex(),
                    "preimage_hex": chain[n_prime - 1].hex()}

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
            "k_1_hex":          k_1.hex(),
            "info_ai":          info_ai,
            "Q_ir":             q_ir,
            "delta_ir":         delta_ir,
            "next_tok":         next_tok,
            # Multi-agent ICP binding.
            "protocol":         "ma",
            "m_root_hex":       tstate["m_root"].hex(),
            "merkle_proof_hex": [p.hex() for p in merkle_proof],
            "leaf_index":       leaf_index,
            "delta_tot":        tstate["delta_tot"],
            "t_exp_icp":        tstate["t_exp"],
        }

        t0 = time.perf_counter()
        sig_init = self.request_signature(canonical_json(m_0))
        costs["XMSS sign sigma^A_I_init"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^A_I_init signed")

        handshake_init = {
            "type":          "handshake_init",
            "m_0":           m_0,
            "sig_ta_ac_hex": contact_info["sig_ta_ac"].hex(),
            "sig_init_hex":  sig_init.hex(),
            "sig_u_icp_hex": tstate["sig_u_icp"].hex(),
        }

        session.send(handshake_init)
        print(f"[BANDWIDTH][AGENT:{self.aid}] -> Handshake init  of size {len(canonical_json(handshake_init))} sent to {aid_r}")
        print(f"[AGENT:{self.aid}] OK Handshake sent to {aid_r}")
        print_crypto_costs(f"Handshake Init (MA): {self.aid}", costs)

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
            "tstate":  tstate,
            # MA chain seed is PRF(sid,...), not PRF(k_1,...).
            "check_rho0_prf": False,
        }

        return {"q_ir": q_ir, "delta_ir": delta_ir}

    
    #  Handshake (receiver) — verifies sigma^U*_ICP + Merkle proof
    
    def _on_handshake_init(self, session, msg):
        # If the initiator is still using 2-agent semantics, delegate.
        m_0 = msg.get("m_0", {})
        if m_0.get("protocol") != "ma":
            return super()._on_handshake_init(session, msg)

        aid_i = session.remote_aid
        print(f"\n[AGENT:{self.aid}] === Handshake recv (MA) "
              f"from {aid_i} ===")

        sig_ta_ac  = bytes.fromhex(msg["sig_ta_ac_hex"])
        sig_init   = bytes.fromhex(msg["sig_init_hex"])
        sig_u_icp  = bytes.fromhex(msg["sig_u_icp_hex"])

        info     = m_0["info_ai"]
        q_ir     = m_0["Q_ir"]
        delta_ir = m_0["delta_ir"]
        next_tok = m_0["next_tok"]
        k_1      = bytes.fromhex(m_0["k_1_hex"])
        id_pk_i  = bytes.fromhex(info["id_pk_i_hex"])
        cert_u_i = info["cert_u_i"]
        cert_a_i = info["cert_a_i"]

        m_root       = bytes.fromhex(m_0["m_root_hex"])
        merkle_proof = [bytes.fromhex(p) for p in m_0["merkle_proof_hex"]]
        leaf_index   = int(m_0["leaf_index"])
        delta_tot    = int(m_0["delta_tot"])
        t_exp_icp    = int(m_0["t_exp_icp"])

        costs = {}

        # Cert_U_I
        t0 = time.perf_counter()
        if not self._ca.verify_cert(cert_u_i):
            raise RuntimeError("Cert_U_I verification failed")
        costs["ML-DSA-65 verify Cert_U_I"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK Cert_U_I valid")

        # Cert_A_I
        t0 = time.perf_counter()
        if not self._ca.verify_cert(cert_a_i):
            raise RuntimeError("Cert_A_I verification failed")
        costs["ML-DSA-65 verify Cert_A_I"] = time.perf_counter() - t0
        if cert_a_i.get("subject") != aid_i:
            raise RuntimeError("Cert_A_I subject mismatch")
        print(f"[AGENT:{self.aid}] OK Cert_A_I valid")

        # sigma^A_I_init over m_0
        t0 = time.perf_counter()
        if not self._xmss.verify(canonical_json(m_0), sig_init, id_pk_i):
            raise RuntimeError("sigma^A_I_init verification failed")
        costs["XMSS verify sigma^A_I_init"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^A_I_init valid")

        # sigma^TA_ac presence
        print(f"[AGENT:{self.aid}] OK sigma^TA_ac present "
              f"({len(sig_ta_ac)}B)")

        # sigma^U*_ICP over <T_exp, A*_I, Mroot, Delta_tot>
        pk_u_i = pk_from_cert(cert_u_i)
        t0 = time.perf_counter()
        if not self._xmss.verify(
                build_tuple_message(str(t_exp_icp), aid_i, m_root,
                                     str(delta_tot)),
                sig_u_icp, pk_u_i):
            raise RuntimeError("sigma^U*_ICP verification failed")
        costs["XMSS verify sigma^U*_ICP"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK sigma^U*_ICP valid "
              f"(T_exp={t_exp_icp}, Delta_tot={delta_tot}s)")

        # T_exp sanity — refuse clearly-expired tasks.
        if int(time.time()) > t_exp_icp:
            raise RuntimeError("sigma^U*_ICP expired (T_exp < now)")

        # NextTok: preimage hashes to image at step n'
        image    = bytes.fromhex(next_tok["image_hex"])
        preimage = bytes.fromhex(next_tok["preimage_hex"])
        t0 = time.perf_counter()
        if not verify_chain_element(preimage, q_ir - 1, q_ir,
                                    image, self.aid.encode()):
            raise RuntimeError("NextTok verification failed")
        costs["SHA-256 NextTok chain verify"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK NextTok valid")

        # Merkle proof: image (chain root) is the leaf_index-th leaf of Mroot
        t0 = time.perf_counter()
        if not verify_merkle_proof(m_root, image, merkle_proof, leaf_index):
            raise RuntimeError("Merkle proof verification failed")
        costs["SHA-256 Merkle proof verify"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK Merkle proof valid "
              f"(leaf={leaf_index})")
        print(f"[AGENT:{self.aid}] OK m_0 verified — building m_1 ...")

        # Build m_1 
        k_2 = create_key()
        t0 = time.perf_counter()
        k_sess = sha256(k_1 + k_2)
        costs["SHA-256 k_sess derivation"] = time.perf_counter() - t0

        # Receiver budget + expiry come from own RCP.
        rcp = self.cp.get("rcp", {})
        if not any(c.get("peer_aid") == aid_i
                   for c in rcp.get("allowed_contacts", [])):
            raise RuntimeError(f"{aid_i} not in RCP allowed_contacts")
        q_ri     = int(rcp["Q"])
        delta_ri = int(rcp["delta_sec"])
        t_exp_rcp = rcp.get("expiry", "2099-01-01T00:00:00Z")

        t0 = time.perf_counter()
        seed_r  = prf(k_2, self.aid, aid_i, 0)
        chain_r = personalized_hash_chain(seed_r, q_ri, aid_i.encode())
        costs[f"PRF seed + hash chain (n={q_ri})"] = time.perf_counter() - t0
        s_n         = chain_r[q_ri]
        s_n_minus_1 = chain_r[q_ri - 1]
        print(f"[AGENT:{self.aid}] Receiver chain built "
              f"(n={q_ri}, root={s_n.hex()[:16]}...)")
        t0 = time.perf_counter()
        sig_u_r_cp = self._user.user_xmss_sign(
            build_tuple_message(t_exp_rcp, self.aid, aid_i, s_n,
                                q_ri, delta_ri))
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

        # Receiver communicates its own RCP t_exp back via session state
        # so _on_data_* inherits work unchanged; the initiator pulled its
        # t_exp from the provider's response already.

        handshake_resp = {"type": "handshake_resp", "m_1": m_1,
                      "tag_1_hex": tag_1.hex()}

        session.send(handshake_resp)
        print(f"[BANDWIDTH][AGENT:{self.aid}] -> Handshake response of size {len(canonical_json(handshake_resp))} sent to {aid_i}")
        print(f"[AGENT:{self.aid}] OK Handshake response sent to {aid_i}")
        print_crypto_costs(f"Handshake Recv (MA): {self.aid}", costs)

        session_expiry = time.time() + delta_ir
        self._session_state[aid_i] = {
            "role": "receiver",
            "remote_aid": aid_i,
            "t_exp":   t_exp_rcp,
            "k_1": k_1, "k_2": k_2, "k_sess": k_sess,
            "q_ir": q_ir, "delta_ir": delta_ir,
            "q_ri": q_ri, "delta_ri": delta_ri,
            "chain_r": chain_r,
            "last_s_released_idx": q_ri - 1,
            "last_rho_seen":     preimage,
            "last_rho_seen_idx": q_ir - 1,
            "chain_i_root": image,
            "ctr_rcp": q_ri - 1,
            "ctr_icp": q_ir - 1,
            "session_expiry": session_expiry,
            "round_num": 1,
            # Initiator chain seed is PRF(sid,...), not PRF(k_1,...).
            "check_rho0_prf": False,
        }
        chain_r[q_ri] = None

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

    
    #  Data-transfer — orchestrator-side 
    
    def send_data_request(self, session, req):
        state = self._session_state.get(session.remote_aid)
        if state and state.get("role") == "initiator":
            tstate = state.get("tstate")
            if tstate and time.time() > tstate["t_start"] + tstate["delta_tot"]:
                raise RuntimeError(
                    "ICP Delta_tot expired — task deadline passed")
        return super().send_data_request(session, req)

    
    # Inter-agent communication — workflow driver
    
    def run_workflow(self, workflow, receivers, xmss):
        """Drive the inter-agent-communication phase end-to-end.

        Resets the orchestrator's LLM once at workflow start so the orchestrator
        retains context across all steps. Receiver LLMs
        are reset per-step since they see independent conversations.

        Returns a list of orchestrator-side bandwidth dicts (one per successful
        step), for phase-level aggregation via lib.metrics.
        """
        if self._task_state is None:
            raise RuntimeError(
                f"{self.aid}: run_user_agent_interaction() must be called "
                "before run_workflow()")

        # Reset orchestrator's LLM once per workflow
        if self._app_agent:
            self._app_agent.reset()

        phase_bw = []
        workflow_handoff = ""
        handoff_history = []
        for i, step in enumerate(workflow):
            rx = receivers.get(step["agent_aid"])
            if rx is None:
                print(f"  FAIL  No receiver registered for "
                      f"{step['agent_aid']}")
                break
            ok, bw, handoff = self._run_workflow_step(
                i, step, rx, xmss, workflow_handoff)
            if bw:
                phase_bw.append(bw)
            if handoff:
                workflow_handoff = handoff
                handoff_history.append(handoff)
            if not ok:
                print(f"  Aborting workflow after step {i+1} failure.")
                break

        if len(phase_bw) == len(workflow):
            self._finalize_workflow_artifacts(handoff_history)
        return phase_bw

    def _finalize_workflow_artifacts(self, handoff_history):
        """Persist deterministic final artifacts for MA tasks after successful steps."""
        if not self._task_state:
            return

        task_text = (self._task_state.get("task") or "").lower()
        if "expense report" in task_text:
            self._write_expense_artifact(handoff_history)

        if "ma_ai_privacy_blog_post.md" in task_text or "blog post" in task_text:
            self._write_blog_artifact(handoff_history)

    def _handoff_facts(self, handoff: str) -> str:
        lines = [ln.rstrip() for ln in (handoff or "").splitlines()]
        facts_started = False
        facts = []
        for line in lines:
            stripped = line.strip()
            if stripped == "- Receiver-provided facts:":
                facts_started = True
                continue
            if not facts_started:
                continue
            if stripped.startswith("- Source agent:"):
                continue
            if stripped:
                facts.append(stripped)
        return "\n".join(facts).strip()

    def _write_expense_artifact(self, handoff_history):
        out_path = os.path.join(ROOT_DIR, "data", "MA_NeurIPS_Expense_Report.txt")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        lines = [
            "Combined NeurIPS Expense Report",
            "",
            f"Orchestrator: {self.aid}",
            "",
        ]
        for idx, handoff in enumerate(handoff_history, start=1):
            lines.append(f"Step {idx} receiver facts:")
            lines.append(self._handoff_facts(handoff) or "(no facts captured)")
            lines.append("")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines).rstrip() + "\n")
        print(f"[AGENT:{self.aid}] Saved combined expense artifact: {out_path}")

    def _write_blog_artifact(self, handoff_history):
        out_path = os.path.join(ROOT_DIR, "MA_AI_Privacy_Blog_Post.md")
        sections = []
        for handoff in handoff_history:
            facts = self._handoff_facts(handoff)
            if facts:
                sections.append(facts)

        content = [
            "# AI Privacy Blog Post",
            "",
            "## Combined Perspectives",
            "",
            "\n\n".join(sections) if sections else "No perspective data captured.",
            "",
        ]
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(content))
        print(f"[AGENT:{self.aid}] Saved blog artifact: {out_path}")

    def _build_step_task(
            self,
            instruction: str,
            workflow_handoff: str,
            target_aid: str,
            is_final_step: bool) -> str:
        """Compose a orchestrator-role step task with explicit carried context."""
        lines = [
            f"You are the orchestrator coordinator agent {self.aid}.",
            f"In this step you are talking only to {target_aid}.",
            "Do NOT role-play as the receiver agent.",
            "Treat the instruction below as receiver-context only, not your identity:",
            instruction,
            "Never ask this receiver for another receiver's data unless explicitly provided as context.",
            "Do not fabricate or infer peer-specific facts (availability, expenses, drafts).",
            "Peer-specific facts are valid only if received from this peer in this session or from verified carried context.",
        ]

        if workflow_handoff:
            lines.extend([
                "",
                "Verified context from previous workflow step(s):",
                workflow_handoff,
                "Use this carried context as factual for this step.",
                "Do not ask for it again unless there is a direct conflict.",
            ])

        if is_final_step:
            lines.extend([
                "",
                "Step completion rule:",
                "Use the carried context plus this receiver's data to finalize the task outcome.",
                "When the outcome is complete, emit <TASK_FINISHED>.",
            ])
        else:
            lines.extend([
                "",
                "Step completion rule:",
                "Collect this receiver's required information and acknowledge receipt.",
                "Do not attempt final global actions in this step.",
                "As soon as required information is collected, emit <TASK_FINISHED> to end this step.",
            ])

        return "\n".join(lines)

    def _extract_step_handoff(self, convo_result: dict, target_aid: str) -> str:
        """Extract concise factual handoff context from a finished step."""
        if not convo_result:
            return ""

        transcript = convo_result.get("transcript") or []
        if not transcript:
            return ""

        incoming_msgs = []

        def _clean_receiver_msg(text: str) -> str:
            # Strip any tool-call wrappers so only peer facts are carried forward.
            cleaned = re.sub(
                r"<\s*tool_call\s*>.*?(<\s*/\s*tool_call\s*>|<\s*/\s*tool_ca\b|$)",
                "",
                text,
                flags=re.IGNORECASE | re.DOTALL,
            )
            return cleaned.strip()

        for turn in transcript:
            if turn.get("role") != "receiver":
                continue
            msg = (turn.get("msg") or "").strip()
            if not msg:
                continue
            if re.search(r'<\s*task[\s_]*finished\s*>', msg, re.IGNORECASE):
                continue
            msg = _clean_receiver_msg(msg)
            if not msg:
                continue
            incoming_msgs.append(msg)

        if not incoming_msgs:
            return ""

        time_pat = r"\b\d{1,2}:\d{2}\s*-\s*\d{1,2}:\d{2}\b"
        slot_msgs = [m for m in incoming_msgs if re.search(time_pat, m)]

        selected = slot_msgs[:2] if slot_msgs else incoming_msgs[-2:]
        selected = selected[-2:]

        lines = [
            f"- Source agent: {target_aid}",
            "- Receiver-provided facts:",
        ]
        for m in selected:
            lines.append(f"  {m}")
        return "\n".join(lines)

    def _build_first_peer_request(self, instruction: str) -> str:
        """Return a task-specific first request to anchor the step domain."""
        task_text = ""
        if self._task_state:
            task_text = self._task_state.get("task", "") or ""
        t = f"{instruction or ''}\n{task_text}".lower()
        if "expense" in t or "inbox" in t or "trip" in t:
            return (
                "Please check your inbox now and share your verified trip expense "
                "items (with amounts) plus your email ID for this task."
            )
        if "blog" in t or "draft" in t or "perspective" in t:
            return (
                "Please read your existing blog material and share your key "
                "perspective plus a draft paragraph for this task."
            )
        if "meeting" in t or "availability" in t or "free 30-minute" in t:
            return (
                "Please check your availability and share your verified free "
                "30-minute slots for the requested date."
            )
        return (
            "Please provide your own verified task data for this step using "
            "your tools and the current task context."
        )

    def _run_workflow_step(self, step_idx, step, rx_agent, xmss, workflow_handoff):
        """One workflow step: spawn the receiver's loop, handshake, run
        the LLM exchange, then both sessions are terminated
        and crypto state wiped — even on handshake or LLM failure.

        Only the receiver's LLM is reset here; the orchestrator's LLM retains
        context across the whole workflow (that reset happens once in
        run_workflow()).

        Returns (success: bool, bw_ orchestrator: dict|None).
        """
        target_aid  = step["agent_aid"]
        instruction = step["instruction"]
        workflow = self._task_state.get("workflow", []) if self._task_state else []
        is_final_step = bool(workflow) and step_idx == (len(workflow) - 1)
        step_task   = self._build_step_task(
            instruction, workflow_handoff, target_aid, is_final_step)
        banner(f"Step {step_idx+1}: {self.aid}  ->  {target_aid}")

        if rx_agent._app_agent:
            rx_agent._app_agent.reset()

        rx_result = {}
        rx_thread = threading.Thread(
            target=rx_agent.run_receiver_loop,
            args=(rx_result,), daemon=True)
        rx_thread.start()

        try:
            orchestrator_result = self.start_A_session(target_aid, xmss)
        except Exception as e:
            print(f"  FAIL  A-session setup to {target_aid}: {e}")
            rx_thread.join(timeout=5)
            return False, None, ""

        orchestrator_session = orchestrator_result.get("session")

        deadline = time.time() + 5
        while rx_result.get("handshake") is None and time.time() < deadline:
            time.sleep(0.05)

        recv_hs      = rx_result.get("handshake")
        recv_session = rx_result.get("session")
        if not ( orchestrator_session and recv_session and recv_hs):
            print(f"  FAIL  A-session handshake with {target_aid}")

            if orchestrator_session:
                self.terminate_A_session( orchestrator_session)
            rx_thread.join(timeout=5)
            if recv_session:
                rx_agent.terminate_A_session(recv_session)
            return False, None, ""

        print(f"\n  OK  A-session {self.aid} -> {target_aid}")
        print(f"      Q_IR={ orchestrator_result['q_ir']}  "
              f"Q_RI={ orchestrator_result['q_ri']}")
        print(f"      k_sess match: "
              f"{ orchestrator_result.get('k_sess') == recv_hs['k_sess']}")

        # Wrap the LLM conversation so sessions are ALWAYS terminated even
        # if the model call raises (timeout, quota, policy hit mid-round).
        success   = False
        bw_orchestrator = None
        handoff   = ""
        try:
            print(f"\n  --- LLM conversation (step {step_idx+1}) ---")
            first_outgoing = self._build_first_peer_request(instruction)
            convo_result = self.run_llm_conversation(
                orchestrator_session,
                step_task,
                max_rounds=6,
                min_peer_rounds_before_finish=1,
                force_first_peer_request=True,
                first_outgoing=first_outgoing,
                auto_finish_after_first_peer_data=not is_final_step)
            handoff = self._extract_step_handoff(convo_result, target_aid)
            success = bool(convo_result and convo_result.get("finished"))
            if not success:
                reason = (convo_result or {}).get("reason", "unknown")
                print(f"  FAIL  Step {step_idx+1} did not finish: {reason}")
        except Exception as e:
            print(f"  FAIL  LLM conversation at step {step_idx+1}: "
                  f"{type(e).__name__}: {e}")
        finally:
            bw_orchestrator = self.terminate_A_session( orchestrator_session)
            rx_thread.join(timeout=5)
            rx_agent.terminate_A_session(recv_session)

        return success, bw_orchestrator, handoff
