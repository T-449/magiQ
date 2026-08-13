import glob
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from agent import Agent
from agent_ma import AgentMA
from ca import CertificateAuthority
from lib.common import ROOT_DIR, certs_dir, load_config
from lib.crypto import XMSSWrapper, XMSS_ALGO
from lib.tls_channel import TLSClient, TLSServer, generate_tls_certs
from provider import Provider
from user import User

CFG = load_config()
ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 10
PAYLOAD = int(sys.argv[2]) if len(sys.argv) > 2 else 0
REPS = int(sys.argv[3]) if len(sys.argv) > 3 else 1


def stub_app_layer(agent, size):
    """Replace the LLM application layer with a fixed-size responder."""
    reply = "R" * size
    agent._app_agent = None
    agent._handle_app_request = lambda req, _reply=reply: {"msg": _reply}


def _load_users():
    pattern = os.path.join(ROOT_DIR, CFG["paths"]["data_users"], "*.json")
    users = []
    for path in sorted(glob.glob(pattern)):
        with open(path) as f:
            users.append(json.load(f))
    return users


def setup(agent_cls):
    xmss = XMSSWrapper()
    ca = CertificateAuthority()
    ca.init_keys()
    prov = Provider(xmss)
    prov.init_keys(ca)
    tls_paths = generate_tls_certs(certs_dir("tls"))
    server = TLSServer(tls_paths, prov.handle_request)
    server.start()
    client = TLSClient(tls_paths)

    users, agents = {}, []
    for user_data in _load_users():
        user = User(user_data=user_data, xmss=xmss, tls_client=client,
                    tls_paths=tls_paths, agent_cls=agent_cls)
        users[user_data["uid"]] = user
        user.register(ca)
        user.register_agents(ca)
        agents.extend(user.agents.values())

    for agent in agents:
        agent._xmss = xmss
        stub_app_layer(agent, PAYLOAD)
    return xmss, client, server, users, agents


def teardown(xmss, server, agents):
    for agent in agents:
        agent.stop_listener()
    server.stop()
    try:
        xmss.cleanup()
    except Exception:
        pass
    time.sleep(0.3)


def drive_session(initiator, receiver, xmss, rounds):
    """Run one A-session and return (handshake, control, data, rounds_done)."""
    rx = {}
    thread = threading.Thread(target=receiver.run_receiver_loop, args=(rx,),
                              daemon=True)
    thread.start()
    session = initiator.start_A_session(receiver.aid, xmss)["session"]

    deadline = time.time() + 15
    while rx.get("handshake") is None and time.time() < deadline:
        time.sleep(0.02)
    if rx.get("handshake") is None:
        raise RuntimeError("handshake did not complete")

    handshake = dict(session.bandwidth_stats())

    done = 0
    for i in range(rounds):
        try:
            initiator.send_data_request(session, {"msg": "Q" * PAYLOAD})
            done += 1
        except RuntimeError as e:
            print(f"  [stop at round {i + 1}] {e}")
            break

    total = session.bandwidth_stats()
    data = total.get("data", {"sent": 0, "recv": 0})
    initiator.terminate_A_session(session)
    thread.join(timeout=5)
    if rx.get("session"):
        receiver.terminate_A_session(rx["session"])

    return (handshake.get("handshake", {"sent": 0, "recv": 0}),
            total.get("control", {"sent": 0, "recv": 0}),
            data, done)


def per_action(client):
    """Average per-message TLS payload sizes, keyed by provider action."""
    out = {}
    for action, stats in client.bandwidth_by_action().items():
        n = max(stats["msg_sent"], 1)
        out[action] = {"sent": stats["sent"] / n,
                       "recv": stats["recv"] / n, "n": n}
    return out


def run_two_agent():
    print("\n" + "=" * 70 + "\n  TWO-AGENT\n" + "=" * 70)
    xmss, client, server, users, agents = setup(Agent)
    try:
        bob = users["bob@domain.com"].agents["bob@domain.com:agent-beta"]
        alice = users["alice@domain.com"].agents["alice@domain.com:agent-alpha"]
        reg = per_action(client)
        for r in range(REPS):
            print(f"\n===== two-agent A-session rep {r + 1}/{REPS} =====")
            handshake, control, data, done = drive_session(bob, alice, xmss,
                                                           ROUNDS)
        return {"reg": reg, "contact": per_action(client).get("contact_request"),
                "handshake": handshake, "control": control, "data": data,
                "rounds": done}
    finally:
        teardown(xmss, server, agents)


def run_multi_agent():
    print("\n" + "=" * 70 + "\n  MULTI-AGENT (1 orchestrator + 2 receivers)\n"
          + "=" * 70)
    xmss, client, server, users, agents = setup(AgentMA)
    try:
        orch = users["bob@domain.com"].agents["bob@domain.com:agent-beta"]
        workflow = [
            {"agent_aid": "alice@domain.com:agent-alpha", "instruction": "step 1"},
            {"agent_aid": "mallory@domain.com:agent-gamma", "instruction": "step 2"},
        ]
        reg = per_action(client)
        per_step = []
        for r in range(REPS):
            print(f"\n===== C-session rep {r + 1}/{REPS} =====")
            orch.run_user_agent_interaction("bandwidth measurement task",
                                            workflow, xmss)
            per_step = []
            for idx, step in enumerate(workflow):
                aid = step["agent_aid"]
                receiver = users[aid.split(":")[0]].agents[aid]
                orch._task_state["current_step"] = idx
                handshake, control, data, done = drive_session(
                    orch, receiver, xmss, ROUNDS)
                per_step.append({"peer": aid, "handshake": handshake,
                                 "control": control, "data": data,
                                 "rounds": done})
            orch.reset_task_state()
        return {"reg": reg, "contact": per_action(client).get("contact_request"),
                "steps": per_step}
    finally:
        teardown(xmss, server, agents)


def kb(n):
    return n / 1024.0


def report(two, ma):
    def total(d):
        return d.get("sent", 0) + d.get("recv", 0)

    print("\n\n" + "#" * 78)
    print(f"#  BANDWIDTH PER PHASE   (XMSS={XMSS_ALGO}, "
          f"payload={PAYLOAD} chars, rounds={ROUNDS})")
    print("#" * 78)

    user_reg = two["reg"]["register_user"]
    agent_reg = two["reg"]["register_agent"]
    contact = two["contact"]

    print(f"\n{'Phase':<42}{'sent B':>10}{'recv B':>10}{'total KB':>11}")
    print("-" * 73)
    print(f"{'User registration (per user)':<42}{user_reg['sent']:>10.0f}"
          f"{user_reg['recv']:>10.0f}"
          f"{kb(user_reg['sent'] + user_reg['recv']):>11.2f}")
    print(f"{'Agent registration (per agent)':<42}{agent_reg['sent']:>10.0f}"
          f"{agent_reg['recv']:>10.0f}"
          f"{kb(agent_reg['sent'] + agent_reg['recv']):>11.2f}")
    print(f"{'Agent discovery / contact req (per A-ses)':<42}"
          f"{contact['sent']:>10.0f}{contact['recv']:>10.0f}"
          f"{kb(contact['sent'] + contact['recv']):>11.2f}")

    print(f"\n--- TWO-AGENT ({two['rounds']} data rounds) ---")
    handshake, control, data = two["handshake"], two["control"], two["data"]
    two_agent_comm = total(handshake) + total(control) + total(contact)
    rounds = max(two["rounds"], 1)
    print(f"{'A-session handshake':<42}{handshake['sent']:>10}"
          f"{handshake['recv']:>10}{kb(total(handshake)):>11.2f}")
    print(f"{'  cert_exchange (control)':<42}{control['sent']:>10}"
          f"{control['recv']:>10}{kb(total(control)):>11.2f}")
    print(f"{'Agent communication (per session, total)':<42}{'':>10}{'':>10}"
          f"{kb(two_agent_comm):>11.2f}")
    print(f"{'Data transfer (per request)':<42}{data['sent'] / rounds:>10.0f}"
          f"{data['recv'] / rounds:>10.0f}{kb(total(data) / rounds):>11.2f}")
    print(f"{'Data transfer (all rounds)':<42}{data['sent']:>10}"
          f"{data['recv']:>10}{kb(total(data)):>11.2f}")

    print("\n--- MULTI-AGENT (t=2 receivers) ---")
    ma_comm = 0
    for step in ma["steps"]:
        handshake, control, data = step["handshake"], step["control"], step["data"]
        step_comm = total(handshake) + total(control) + total(contact)
        ma_comm += step_comm
        rounds = max(step["rounds"], 1)
        print(f"  {step['peer']}  ({step['rounds']} rounds)")
        print(f"{'    A-session handshake':<42}{handshake['sent']:>10}"
              f"{handshake['recv']:>10}{kb(total(handshake)):>11.2f}")
        print(f"{'    agent comm (incl. discovery)':<42}{'':>10}{'':>10}"
              f"{kb(step_comm):>11.2f}")
        print(f"{'    data transfer (per request)':<42}"
              f"{data['sent'] / rounds:>10.0f}{data['recv'] / rounds:>10.0f}"
              f"{kb(total(data) / rounds):>11.2f}")
    print(f"{'  Agent communication (C-session total)':<42}{'':>10}{'':>10}"
          f"{kb(ma_comm):>11.2f}")
    print(f"\n  two-agent agent-comm   = {kb(two_agent_comm):.2f} KB")
    print(f"  multi-agent agent-comm = {kb(ma_comm):.2f} KB  "
          f"({ma_comm / two_agent_comm:.2f}x for t=2)")

    out_path = os.path.join(HERE, "bw_results.json")
    with open(out_path, "w") as f:
        json.dump({"xmss": XMSS_ALGO, "payload": PAYLOAD, "rounds": ROUNDS,
                   "two_agent": two, "multi_agent": ma}, f, indent=2,
                  default=str)
    print(f"\n  raw results -> {out_path}")


if __name__ == "__main__":
    t0 = time.time()
    report(run_two_agent(), run_multi_agent())
    print(f"\n  wall time {time.time() - t0:.1f}s")
