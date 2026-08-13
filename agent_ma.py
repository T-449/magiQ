import os
import re
import threading
import time

from lib.common import (
    ROOT_DIR, b64e, b64d,
    build_tuple_message, create_key, prf, sha256, canonical_json,
    personalized_hash_chain, verify_chain_element,
    build_merkle_tree, get_merkle_proof, verify_merkle_proof,
    icp_time_leaf,
)
from lib.crypto import pk_from_cert
from lib.metrics import banner, print_crypto_costs

from agent import Agent


class AgentMA(Agent):
    """Agent with the C-session enabled."""

    def __init__(self, agent_data, policy):
        super().__init__(agent_data, policy)
        # Orchestrator-side ICP state, None between tasks.
        self._task_state = None

    def run_user_agent_interaction(self, task, workflow, xmss):
        """
        Args:
            task:     high-level task description.
            workflow: list of {"agent_aid", "instruction"}, in contact order.
            xmss:     XMSS wrapper.
        """
        self._xmss = xmss
        if not workflow:
            raise RuntimeError("workflow is empty")

        icp = self.cp.get("icp", {})
        if not icp:
            raise RuntimeError(f"Agent {self.aid}: no ICP in policy")

        n_prime = int(icp["n_prime"])
        delta_tot = int(icp["delta_tot_sec"])
        t_agents = len(workflow)
        m = int(icp.get("m", t_agents))
        q_tot = int(icp["Q_tot"])
        if m < t_agents:
            raise RuntimeError(f"ICP m ({m}) is below t ({t_agents}), "
                               "at least one chain per agent is required")
        if m * n_prime > q_tot:
            raise RuntimeError(f"ICP m*n' ({m}*{n_prime}) exceeds Q_tot ({q_tot})")

        # The first t chains cover each agent once, any spare chains wrap round.
        agent_list = [w["agent_aid"] for w in workflow]
        assignments = list(agent_list) + [
            agent_list[i % t_agents] for i in range(m - t_agents)]

        sid = create_key(16)
        addr = f"{self.ed['ip']}:{self.ed['port']}"

        costs = {}
        print(f"\n[AGENT:{self.aid}] === (i) User-Agent Interaction ===")
        print(f"[AGENT:{self.aid}] Workflow: "
              + ", ".join(f"{i + 1}.{w['agent_aid']}"
                          for i, w in enumerate(workflow)))
        print(f"[AGENT:{self.aid}] ICP: m={m}, n'={n_prime}, "
              f"Delta_tot={delta_tot}s (Q_tot={m * n_prime})")

        t0 = time.perf_counter()
        chains = []
        for i, aid_j in enumerate(assignments):
            seed = prf(sid, self.aid, aid_j, f"{addr}:{i}")
            chains.append({"agent_aid": aid_j, "seed": seed,
                           "chain": personalized_hash_chain(
                               seed, n_prime, aid_j.encode())})
        costs[f"PRF seeds + {m} hash chains (n'={n_prime})"] = \
            time.perf_counter() - t0

        base = delta_tot // t_agents
        rem = delta_tot - base * t_agents
        deltas = [(w["agent_aid"], base + (1 if i < rem else 0))
                  for i, w in enumerate(workflow)]
        print(f"[AGENT:{self.aid}] Time allocation: "
              + ", ".join(f"{a}={d}s" for a, d in deltas)
              + f"  (sum={sum(d for _, d in deltas)}<={delta_tot}s)")

        # Two Merkle trees, one over the m chain roots and one over the t time budgets. 
        t0 = time.perf_counter()
        leaves_msg = [c["chain"][n_prime] for c in chains]
        m_root, m_levels = build_merkle_tree(leaves_msg)
        costs[f"Merkle tree msg ({m} leaves)"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        leaves_time = [icp_time_leaf(j, peer, d)
                       for j, (peer, d) in enumerate(deltas)]
        m_root_time, m_levels_time = build_merkle_tree(leaves_time)
        costs[f"Merkle tree time ({t_agents} leaves)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] Mroot_msg={m_root.hex()[:16]}...  "
              f"Mroot_time={m_root_time.hex()[:16]}...")

        t0 = time.perf_counter()
        sig_u_icp, tau_start, u_root_msg, u_root_time = \
            self._user.user_sign_icp(self.aid, leaves_msg, deltas, n_prime)
        costs["XMSS sign tok^msg+Time (ICP)"] = time.perf_counter() - t0
        if (u_root_msg, u_root_time) != (m_root, m_root_time):
            raise RuntimeError("user-recomputed Merkle roots disagree with local")
        print(f"[AGENT:{self.aid}] OK tok^msg+Time (ICP) signed "
              f"(tau_start={tau_start})")

        t0 = time.perf_counter()
        if not xmss.verify(
                build_tuple_message(m_root, m_root_time, tau_start,
                                    n_prime, m, t_agents, q_tot, delta_tot),
                sig_u_icp, self._user.id_pk):
            raise RuntimeError("tok^msg+Time (ICP) self-verification failed")
        costs["XMSS verify tok^msg+Time (ICP)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK ICP token verified, both trees stored")

        self._task_state = {
            "task": task,
            "workflow": workflow,
            "n_prime": n_prime,
            "m": m,
            "delta_tot": delta_tot,
            "sid": sid,
            "addr": addr,
            "chains": chains,
            "q_tot": q_tot,
            "t_agents": t_agents,
            "m_root": m_root,
            "m_levels": m_levels,
            "m_root_time": m_root_time,
            "m_levels_time": m_levels_time,
            "deltas": deltas,
            "sig_u_icp": sig_u_icp,
            "tau_start": tau_start,
            "t_start": time.time(),
            # How many chains for a given aid have been consumed.
            "chain_next": {},
            # Peer aid to workflow position, which is its time-leaf index.
            "step_index": {},
        }

        print_crypto_costs(f"User-Agent Interaction: {self.aid}", costs)
        return self._task_state

    def reset_task_state(self):
        """Scrub the ICP chains and seeds between tasks."""
        if self._task_state is None:
            return
        for entry in self._task_state.get("chains", []):
            chain = entry.get("chain")
            if chain:
                for i in range(len(chain)):
                    chain[i] = None
            seed = entry.get("seed")
            if seed:
                entry["seed"] = b"\x00" * len(seed)
        self._task_state = None

    def cleanup_task(self, receivers):
        """Wipe every A-session key, LLM history and ICP tree after a task."""
        for agent in (self, *receivers.values()):
            remaining = list(agent._session_state.keys())
            if not remaining:
                continue
            for remote_aid in remaining:
                state = agent._session_state.pop(remote_aid, {})
                for key in ("k_1", "k_2", "k_sess"):
                    value = state.get(key)
                    if value:
                        state[key] = b"\x00" * len(value)
                for chain_key in ("chain_i", "chain_r"):
                    chain = state.get(chain_key)
                    if chain:
                        for i in range(len(chain)):
                            chain[i] = None
                state.clear()
            print(f"[AGENT:{agent.aid}] Wiped {len(remaining)} "
                  f"leftover A-session state(s)")

        for agent in (self, *receivers.values()):
            if agent._app_agent:
                agent._app_agent.reset()
            agent._llm_total_calls = 0
            agent._llm_total_sec = 0.0
            agent._llm_by_label.clear()

        self.reset_task_state()

    def _handshake_initiator(self, session, contact_info):
        """Send m_0 carrying a pre-generated chain and its two Merkle proofs."""
        aid_r = contact_info["aid_r"]
        t_exp = contact_info["t_exp"]
        print(f"\n[AGENT:{self.aid}] === Handshake (initiator, MA) ===")

        tstate = self._task_state
        if tstate is None:
            raise RuntimeError(
                f"Agent {self.aid}: run_user_agent_interaction() must be "
                "called before start_A_session() in the multi-agent protocol")

        if time.time() > tstate["t_start"] + tstate["delta_tot"]:
            raise RuntimeError("ICP Delta_tot expired, task deadline passed")

        matching = [i for i, c in enumerate(tstate["chains"])
                    if c["agent_aid"] == aid_r]
        if not matching:
            raise RuntimeError(f"No pre-generated chain for {aid_r} in ICP")
        used = tstate["chain_next"].get(aid_r, 0)
        if used >= len(matching):
            raise RuntimeError(f"All ICP chains for {aid_r} consumed")
        leaf_index = matching[used]
        tstate["chain_next"][aid_r] = used + 1

        chain = tstate["chains"][leaf_index]["chain"]
        n_prime = tstate["n_prime"]

        icp = self.cp.get("icp", {})
        if not any(c.get("peer_aid") == aid_r
                   for c in icp.get("allowed_contacts", [])):
            raise RuntimeError(f"{aid_r} not in ICP allowed_contacts")
        q_ir = n_prime

        step_idx = tstate.get("current_step")
        if step_idx is None:
            step_idx = next(j for j, (peer, _) in enumerate(tstate["deltas"])
                            if peer == aid_r)
        peer_at_step, delta_j = tstate["deltas"][step_idx]
        if peer_at_step != aid_r:
            raise RuntimeError(f"time-leaf mismatch: step {step_idx} is "
                               f"{peer_at_step}, not {aid_r}")
        delta_ir = int(delta_j)

        costs = {}
        t0 = time.perf_counter()
        merkle_proof = get_merkle_proof(tstate["m_levels"], leaf_index)
        merkle_proof_time = get_merkle_proof(tstate["m_levels_time"], step_idx)
        costs["Merkle proof fetch (msg + time)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] ICP chain #{leaf_index} -> {aid_r} "
              f"(root={chain[n_prime].hex()[:16]}..., "
              f"depth={len(merkle_proof)})")
        print(f"[AGENT:{self.aid}] Time leaf #{step_idx} Delta_j={delta_ir}s "
              f"(depth={len(merkle_proof_time)})")

        k_1 = create_key()
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
            "next_tok": {"image_b64": b64e(chain[n_prime]),
                         "preimage_b64": b64e(chain[n_prime - 1])},
            "protocol": "ma",
            "m_root_b64": b64e(tstate["m_root"]),
            "merkle_proof_b64": [b64e(p) for p in merkle_proof],
            "leaf_index": leaf_index,
            "m_root_time_b64": b64e(tstate["m_root_time"]),
            "merkle_proof_time_b64": [b64e(p) for p in merkle_proof_time],
            "time_leaf_index": step_idx,
            "delta_tot": tstate["delta_tot"],
            "tau_start": tstate["tau_start"],
            "m": tstate["m"],
            "t_agents": tstate["t_agents"],
            "n_prime": n_prime,
            "Q_tot": tstate["q_tot"],
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
            "sig_u_icp_b64": b64e(tstate["sig_u_icp"]),
        })
        print(f"[AGENT:{self.aid}] OK Handshake sent to {aid_r}")
        print_crypto_costs(f"Handshake Init (MA): {self.aid}", costs)

        self._session_state[aid_r] = {
            "role": "initiator",
            "remote_aid": aid_r,
            "t_exp": t_exp,
            "tau_start": tstate["tau_start"],
            "k_1": k_1,
            "chain_i": chain,
            "q_ir": q_ir,
            "delta_ir": delta_ir,
            "ctr_icp": q_ir - 1,
            "last_rho_released_idx": q_ir - 1,
            "pk_u_r": contact_info["pk_u_r"],
            "session_expiry": time.time() + delta_ir,
            "round_num": 1,
            "tstate": tstate,
            "check_rho0_prf": False,
        }
        return {"q_ir": q_ir, "delta_ir": delta_ir}

    def _on_handshake_init(self, session, msg):
        """Verify the ICP token and both Merkle proofs, then reply with m_1."""
        m_0 = msg.get("m_0", {})
        if m_0.get("protocol") != "ma":
            return super()._on_handshake_init(session, msg)

        aid_i = session.remote_aid
        print(f"\n[AGENT:{self.aid}] === Handshake recv (MA) from {aid_i} ===")

        sig_ta_ac = b64d(msg["sig_ta_ac_b64"])
        sig_init = b64d(msg["sig_init_b64"])
        sig_u_icp = b64d(msg["sig_u_icp_b64"])

        info = m_0["info_ai"]
        q_ir = m_0["Q_ir"]
        delta_ir = m_0["delta_ir"]
        next_tok = m_0["next_tok"]
        k_1 = b64d(m_0["k_1_b64"])
        id_pk_i = b64d(info["id_pk_i_b64"])
        cert_u_i = info["cert_u_i"]
        cert_a_i = info["cert_a_i"]

        m_root = b64d(m_0["m_root_b64"])
        merkle_proof = [b64d(p) for p in m_0["merkle_proof_b64"]]
        leaf_index = int(m_0["leaf_index"])
        delta_tot = int(m_0["delta_tot"])
        m_root_time = b64d(m_0["m_root_time_b64"])
        merkle_proof_time = [b64d(p) for p in m_0["merkle_proof_time_b64"]]
        time_leaf_index = int(m_0["time_leaf_index"])
        tau_start = int(m_0["tau_start"])
        m_chains = int(m_0["m"])
        t_agents = int(m_0["t_agents"])
        n_prime = int(m_0["n_prime"])
        q_tot = int(m_0["Q_tot"])

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

        # Contact-policy enforcement at the receiver.
        t0 = time.perf_counter()
        self.verify_sig_ta_ac(sig_ta_ac, aid_i, id_pk_i)
        costs["XMSS verify sigma^TA_ac"] = time.perf_counter() - t0

        pk_u_i = pk_from_cert(cert_u_i)
        t0 = time.perf_counter()
        if not self._xmss.verify(
                build_tuple_message(m_root, m_root_time, tau_start,
                                    n_prime, m_chains, t_agents,
                                    q_tot, delta_tot),
                sig_u_icp, pk_u_i):
            raise RuntimeError("tok^msg+Time (ICP) verification failed")
        costs["XMSS verify tok^msg+Time (ICP)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK tok^msg+Time (ICP) valid "
              f"(n'={n_prime}, m={m_chains}, t={t_agents}, "
              f"Q_tot={q_tot}, Delta_tot={delta_tot}s)")

        if q_ir != n_prime:
            raise RuntimeError(
                f"declared Q_ir={q_ir} does not match user-signed n'={n_prime}")
        if m_chains * n_prime > q_tot:
            raise RuntimeError("m*n' exceeds the signed Q_tot")

        tau_now = int(time.time())
        if not tau_now - tau_start + delta_ir < delta_tot:
            raise RuntimeError(
                f"C-session time budget exceeded: (tau_now - tau_start) + "
                f"Delta_j = {tau_now - tau_start} + {delta_ir} "
                f">= Delta_tot = {delta_tot}s")
        print(f"[AGENT:{self.aid}] OK C-session time window valid "
              f"({tau_now - tau_start}s elapsed + Delta_j={delta_ir}s "
              f"< Delta_tot={delta_tot}s)")

        image = b64d(next_tok["image_b64"])
        preimage = b64d(next_tok["preimage_b64"])
        t0 = time.perf_counter()
        if not verify_chain_element(preimage, q_ir - 1, q_ir,
                                    image, self.aid.encode()):
            raise RuntimeError("NextTok verification failed")
        costs["SHA-256 NextTok chain verify"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK NextTok valid")

        t0 = time.perf_counter()
        if not verify_merkle_proof(m_root, image, merkle_proof, leaf_index,
                                   n_leaves=m_chains):
            raise RuntimeError("msg Merkle proof verification failed")
        costs["SHA-256 Merkle proof verify (msg)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK msg Merkle proof valid "
              f"(leaf={leaf_index}/{m_chains})")

        t0 = time.perf_counter()
        time_leaf = icp_time_leaf(time_leaf_index, self.aid, delta_ir)
        if not verify_merkle_proof(m_root_time, time_leaf, merkle_proof_time,
                                   time_leaf_index, n_leaves=t_agents):
            raise RuntimeError("time Merkle proof verification failed")
        costs["SHA-256 Merkle proof verify (time)"] = time.perf_counter() - t0
        print(f"[AGENT:{self.aid}] OK time Merkle proof valid "
              f"(leaf={time_leaf_index}/{t_agents}, Delta_j={delta_ir}s)")
        print(f"[AGENT:{self.aid}] OK m_0 verified, building m_1 ...")

        k_2 = create_key()
        t0 = time.perf_counter()
        k_sess = sha256(k_1 + k_2)
        costs["SHA-256 k_sess derivation"] = time.perf_counter() - t0

        rcp = self.cp.get("rcp", {})
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
        print_crypto_costs(f"Handshake Recv (MA): {self.aid}", costs)

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
            "chain_i_root": image,
            "ctr_rcp": q_ri - 1,
            "ctr_icp": q_ir - 1,
            "session_expiry": session_expiry,
            "round_num": 1,
            "check_rho0_prf": False,
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
        """Enforce the task-wide deadline before each request."""
        state = self._session_state.get(session.remote_aid)
        if state and state.get("role") == "initiator":
            tstate = state.get("tstate")
            if tstate and time.time() > tstate["t_start"] + tstate["delta_tot"]:
                raise RuntimeError("ICP Delta_tot expired, task deadline passed")
        return super().send_data_request(session, req)

    def run_workflow(self, workflow, receivers, xmss):
        """Run the inter-agent communication phase end to end."""
        if self._task_state is None:
            raise RuntimeError(
                f"{self.aid}: run_user_agent_interaction() must be called "
                "before run_workflow()")

        if self._app_agent:
            self._app_agent.reset()

        phase_bw = []
        workflow_handoff = ""
        handoff_history = []
        for i, step in enumerate(workflow):
            receiver = receivers.get(step["agent_aid"])
            if receiver is None:
                print(f"  FAIL  No receiver registered for {step['agent_aid']}")
                break
            ok, bw, handoff = self._run_workflow_step(
                i, step, receiver, xmss, workflow_handoff)
            if bw:
                phase_bw.append(bw)
            if handoff:
                handoff_history.append(handoff)
                workflow_handoff = "\n\n".join(handoff_history)
            if not ok:
                print(f"  Aborting workflow after step {i + 1} failure.")
                break

        if len(phase_bw) == len(workflow):
            self._finalize_workflow_artifacts(handoff_history)
        return phase_bw

    def _run_workflow_step(self, step_idx, step, rx_agent, xmss,
                           workflow_handoff):
        target_aid = step["agent_aid"]
        instruction = step["instruction"]
        workflow = self._task_state.get("workflow", []) if self._task_state else []
        is_final_step = bool(workflow) and step_idx == (len(workflow) - 1)
        step_task = self._build_step_task(
            instruction, workflow_handoff, target_aid, is_final_step)
        banner(f"Step {step_idx + 1}: {self.aid}  ->  {target_aid}")

        if rx_agent._app_agent:
            rx_agent._app_agent.reset()

        if self._task_state is not None:
            self._task_state["current_step"] = step_idx

        rx_result = {}
        rx_thread = threading.Thread(target=rx_agent.run_receiver_loop,
                                     args=(rx_result,), daemon=True)
        rx_thread.start()

        try:
            orch_result = self.start_A_session(target_aid, xmss)
        except Exception as e:
            print(f"  FAIL  A-session setup to {target_aid}: {e}")
            rx_thread.join(timeout=5)
            return False, None, ""

        orch_session = orch_result.get("session")

        deadline = time.time() + 5
        while rx_result.get("handshake") is None and time.time() < deadline:
            time.sleep(0.05)

        recv_hs = rx_result.get("handshake")
        recv_session = rx_result.get("session")
        if not (orch_session and recv_session and recv_hs):
            print(f"  FAIL  A-session handshake with {target_aid}")
            if orch_session:
                self.terminate_A_session(orch_session)
            rx_thread.join(timeout=5)
            if recv_session:
                rx_agent.terminate_A_session(recv_session)
            return False, None, ""

        print(f"\n  OK  A-session {self.aid} -> {target_aid}")
        print(f"      Q_IR={orch_result['q_ir']}  Q_RI={orch_result['q_ri']}")
        print(f"      k_sess match: "
              f"{orch_result.get('k_sess') == recv_hs['k_sess']}")

        success = False
        bw_orchestrator = None
        handoff = ""
        try:
            print(f"\n  --- LLM conversation (step {step_idx + 1}) ---")
            convo_result = self.run_llm_conversation(
                orch_session,
                step_task,
                max_rounds=6,
                min_peer_rounds_before_finish=2 if is_final_step else 1,
                force_first_peer_request=True,
                first_outgoing=self._build_first_peer_request(instruction),
                auto_finish_after_first_peer_data=not is_final_step)
            handoff = self._extract_step_handoff(convo_result, target_aid)
            success = bool(convo_result and convo_result.get("finished"))
            if not success:
                reason = (convo_result or {}).get("reason", "unknown")
                print(f"  FAIL  Step {step_idx + 1} did not finish: {reason}")
        except Exception as e:
            print(f"  FAIL  LLM conversation at step {step_idx + 1}: "
                  f"{type(e).__name__}: {e}")
        finally:
            bw_orchestrator = self.terminate_A_session(orch_session)
            rx_thread.join(timeout=5)
            rx_agent.terminate_A_session(recv_session)

        return success, bw_orchestrator, handoff

    def _build_step_task(self, instruction: str, workflow_handoff: str,
                         target_aid: str, is_final_step: bool) -> str:
        lines = [
            f"You are the orchestrator coordinator agent {self.aid}.",
            f"In this step you are talking only to {target_aid}.",
            "Do NOT role-play as the receiver agent.",
            "Treat the instruction below as receiver-context only, "
            "not your identity:",
            instruction,
            "Never ask this receiver for another receiver's data unless "
            "explicitly provided as context.",
            "Do not fabricate or infer peer-specific facts such as "
            "availability, expenses or drafts.",
            "Peer-specific facts are valid only if received from this peer in "
            "this session or from verified carried context.",
        ]

        if workflow_handoff:
            lines.extend([
                "",
                "Verified context from previous workflow step(s):",
                workflow_handoff,
                "Use this carried context as factual for this step.",
                "Do not ask for it again unless there is a direct conflict.",
            ])

        lines.append("")
        lines.append("Step completion rule:")
        if is_final_step:
            lines.extend([
                "Use the carried context plus this receiver's data to finalize "
                "the task outcome.",
                "When the outcome is complete, emit <TASK_FINISHED>.",
            ])
        else:
            lines.extend([
                "Collect this receiver's required information and acknowledge "
                "receipt.",
                "Do not attempt final global actions in this step.",
                "As soon as required information is collected, emit "
                "<TASK_FINISHED> to end this step.",
            ])
        return "\n".join(lines)

    def _build_first_peer_request(self, instruction: str) -> str:
        task_text = ""
        if self._task_state:
            task_text = self._task_state.get("task", "") or ""
        src = f"{instruction or ''}\n{task_text}"
        lowered = src.lower()

        def first(*patterns, flags=re.IGNORECASE, group=0):
            for p in patterns:
                m = re.search(p, src, flags)
                if m:
                    return (m.group(group) or "").strip()
            return ""

        if "expense" in lowered or "inbox" in lowered or "trip" in lowered:
            event = first(r"\bNeurIPS\b")
            dates = first(r"\d{2}-\d{2}\s+to\s+\d{2}-\d{2}")
            place = first(r"\bin\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)",
                          flags=0, group=1)
            trip = ", ".join(x for x in (event, dates, place) if x)
            where = f" for the {trip} trip" if trip else ""
            return (f"Please call check_inbox now and share your verified "
                    f"expense items with amounts{where}, plus your email ID.")

        if "blog" in lowered or "draft" in lowered or "perspective" in lowered:
            topic = first(r"privacy implications of AI",
                          r"blog post on [^.,]{0,60}")
            about = f" on {topic}" if topic else ""
            return (f"Please call read_blog_posts now and share your key "
                    f"perspective{about} plus a short draft paragraph.")

        if ("meeting" in lowered or "availability" in lowered
                or "free 30-minute" in lowered):
            day = first(r"(?:Mon|Tues|Wednes|Thurs|Fri|Satur|Sun)day\s+"
                        r"\d{4}-\d{2}-\d{2}",
                        r"\d{4}-\d{2}-\d{2}")
            on = f" on {day}" if day else ""
            return (f"Please call check_availability now and share your "
                    f"verified free 30-minute slots{on}.")

        return ("Please provide your own verified task data for this step "
                "using your tools and the current task context.")

    def _extract_step_handoff(self, convo_result: dict, target_aid: str) -> str:
        """Pull the receiver's factual statements out of a finished step."""
        if not convo_result:
            return ""
        transcript = convo_result.get("transcript") or []
        if not transcript:
            return ""

        def strip_tool_calls(text: str) -> str:
            return re.sub(
                r"<\s*tool_call\s*>.*?(<\s*/\s*tool_call\s*>|<\s*/\s*tool_ca\b|$)",
                "", text, flags=re.IGNORECASE | re.DOTALL).strip()

        incoming = []
        for turn in transcript:
            if turn.get("role") != "receiver":
                continue
            msg = (turn.get("msg") or "").strip()
            if not msg:
                continue
            if re.search(r"<\s*task[\s_]*finished\s*>", msg, re.IGNORECASE):
                continue
            msg = strip_tool_calls(msg)
            if msg:
                incoming.append(msg)

        if not incoming:
            return ""

        slot_msgs = [m for m in incoming
                     if re.search(r"\b\d{1,2}:\d{2}\s*-\s*\d{1,2}:\d{2}\b", m)]
        selected = (slot_msgs[:2] if slot_msgs else incoming[-2:])[-2:]

        lines = [f"- Source agent: {target_aid}", "- Receiver-provided facts:"]
        lines.extend(f"  {m}" for m in selected)
        return "\n".join(lines)

    def _finalize_workflow_artifacts(self, handoff_history):
        """Write deterministic artifacts once every workflow step succeeded."""
        if not self._task_state:
            return
        task_text = (self._task_state.get("task") or "").lower()
        if "expense report" in task_text:
            self._write_expense_artifact(handoff_history)
        if "blog post" in task_text or "blog_post" in task_text:
            self._write_blog_artifact(handoff_history)

    @staticmethod
    def _handoff_facts(handoff: str) -> str:
        """Return just the fact lines from one handoff block."""
        facts = []
        started = False
        for line in (handoff or "").splitlines():
            stripped = line.strip()
            if stripped == "- Receiver-provided facts:":
                started = True
                continue
            if not started or stripped.startswith("- Source agent:"):
                continue
            if stripped:
                facts.append(stripped)
        return "\n".join(facts).strip()

    def _write_expense_artifact(self, handoff_history):
        out_path = os.path.join(ROOT_DIR, "output",
                                "MA_NeurIPS_Expense_Report_handoff.txt")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        lines = ["Combined NeurIPS Expense Report", "",
                 f"Orchestrator: {self.aid}", ""]
        for idx, handoff in enumerate(handoff_history, start=1):
            lines.append(f"Step {idx} receiver facts:")
            lines.append(self._handoff_facts(handoff) or "(no facts captured)")
            lines.append("")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines).rstrip() + "\n")
        print(f"[AGENT:{self.aid}] Saved combined expense artifact: {out_path}")

    def _write_blog_artifact(self, handoff_history):
        out_path = os.path.join(ROOT_DIR, "output",
                                "MA_AI_Privacy_Blog_Post_handoff.md")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        sections = [facts for facts in
                    (self._handoff_facts(h) for h in handoff_history) if facts]
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
