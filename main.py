import glob
import json
import os
import threading
import time
from collections import namedtuple

from agent import Agent
from agent_ma import AgentMA
from agents_llm import load_model_client
from ca import CertificateAuthority
from lib.common import ROOT_DIR, certs_dir, load_config
from lib.crypto import XMSSWrapper
from lib.metrics import banner, print_llm_summary, print_bandwidth_summary
from lib.tls_channel import TLSClient, TLSServer, generate_tls_certs
from provider import Provider
from user import User

CFG = load_config()
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

PhaseContext = namedtuple(
    "PhaseContext",
    "users all_agents xmss ca prov tls_client tls_server tls_paths")


def _load_user_files():
    pattern = os.path.join(ROOT_DIR, CFG["paths"]["data_users"], "*.json")
    users = []
    for path in sorted(glob.glob(pattern)):
        with open(path) as f:
            users.append(json.load(f))
    return users


def agent_by_aid(users, aid):
    """Resolve 'user@host:agent-name' to its registered Agent."""
    return users[aid.split(":")[0]].agents[aid]


def setup_phase(agent_cls, label):
    """Stand up a phase: CA, provider, PQ-TLS, registered users and agents."""
    banner(f"{label}: Initialise")
    xmss = XMSSWrapper()
    ca = CertificateAuthority()
    ca.init_keys()

    prov = Provider(xmss)
    prov.init_keys(ca)

    tls_paths = generate_tls_certs(certs_dir("tls"))
    tls_server = TLSServer(tls_paths, prov.handle_request)
    tls_server.start()
    tls_client = TLSClient(tls_paths)

    users = {}
    all_agents = []
    for user_data in _load_user_files():
        user = User(user_data=user_data, xmss=xmss, tls_client=tls_client,
                    tls_paths=tls_paths, agent_cls=agent_cls)
        users[user_data["uid"]] = user
        user.register(ca)
        user.register_agents(ca)
        all_agents.extend(user.agents.values())

    for agent in all_agents:
        agent._xmss = xmss

    return PhaseContext(users=users, all_agents=all_agents, xmss=xmss, ca=ca,
                        prov=prov, tls_client=tls_client,
                        tls_server=tls_server, tls_paths=tls_paths)


def teardown_phase(ctx):
    for agent in ctx.all_agents:
        agent.close_llm()
        agent.stop_listener()
    if ctx.tls_server:
        ctx.tls_server.stop()
    ctx.xmss.cleanup()
    time.sleep(0.3)


def attach_llms(all_agents):
    model_client = load_model_client(os.path.join(SCRIPT_DIR, "llm.yaml"))
    for agent in all_agents:
        agent.attach_llm(model_client)


def reset_agent_contexts(all_agents):
    """Reset model context and LLM counters at task boundaries."""
    for agent in all_agents:
        if agent._app_agent:
            agent._app_agent.reset()
        agent._llm_total_calls = 0
        agent._llm_total_sec = 0.0
        agent._llm_by_label.clear()


def run_two_agent_task(task_name, task, initiator, receiver, xmss):
    """Run one task over a single A-session between two agents."""
    banner(task_name)

    if initiator._app_agent:
        initiator._app_agent.reset()
    if receiver._app_agent:
        receiver._app_agent.reset()

    rx_result = {}
    rx_thread = threading.Thread(target=receiver.run_receiver_loop,
                                 args=(rx_result,), daemon=True)
    rx_thread.start()

    init_result = initiator.start_A_session(receiver.aid, xmss)
    init_session = init_result.get("session")

    deadline = time.time() + 5
    while rx_result.get("handshake") is None and time.time() < deadline:
        time.sleep(0.05)

    rx_hs = rx_result.get("handshake")
    rx_session = rx_result.get("session")
    if not (init_session and rx_session and rx_hs):
        print(f"  FAIL  A-Session setup for '{task_name}'")
        if init_session:
            init_session.close()
        rx_thread.join(timeout=5)
        return False

    print(f"\n  OK  A-session {initiator.aid} -> {receiver.aid}")
    print(f"      Q_IR={init_result['q_ir']}  Q_RI={init_result['q_ri']}")
    print(f"      k_sess match: {init_result.get('k_sess') == rx_hs['k_sess']}")

    print("\n  - LLM conversation -")
    initiator.run_llm_conversation(init_session, task)

    initiator.terminate_A_session(init_session)
    rx_thread.join(timeout=5)
    receiver.terminate_A_session(rx_session)
    return True


def run_ma_task(task_name, task, workflow, orchestrator, receivers, xmss):
    """Run one task as a C-session across a multi-step workflow."""
    banner(task_name)
    print(f"\n[TASK] {task}\n")
    try:
        banner(f"(i) User-Agent Interaction (orchestrator: {orchestrator.aid})")
        orchestrator.run_user_agent_interaction(task, workflow, xmss)

        banner("(ii) Inter-Agent Communication")
        phase_bw = orchestrator.run_workflow(workflow, receivers, xmss)

        banner(f"{task_name} Summary")
        print_llm_summary(
            "Multi-Agent LLM Cost",
            [orchestrator] + list(receivers.values()),
            role_fn=lambda a: "orchestrator" if a is orchestrator else "receiver")
        print_bandwidth_summary(
            "Multi-Agent Session Totals (orchestrator perspective)", phase_bw)

        return len(phase_bw) == len(workflow)
    finally:
        orchestrator.cleanup_task(receivers)


def run_phase_a(tasks):
    """Two-agent phase. Each task names its initiator and receiver."""
    ctx = setup_phase(Agent, "PHASE A (two-agent)")
    try:
        attach_llms(ctx.all_agents)
        for task_def in tasks:
            initiator = agent_by_aid(ctx.users, task_def["initiator"])
            receiver = agent_by_aid(ctx.users, task_def["receiver"])
            ok = run_two_agent_task(task_def["name"], task_def["task"],
                                    initiator, receiver, ctx.xmss)
            reset_agent_contexts(ctx.all_agents)
            if not ok:
                break
    finally:
        teardown_phase(ctx)


def run_phase_b(tasks):
    """Multi-agent phase. Each task names its orchestrator and workflow."""
    ctx = setup_phase(AgentMA, "PHASE B (multi-agent)")
    try:
        attach_llms(ctx.all_agents)
        for task_def in tasks:
            orchestrator = agent_by_aid(ctx.users, task_def["orchestrator"])
            workflow = task_def["workflow"]
            receivers = {step["agent_aid"]: agent_by_aid(ctx.users,
                                                         step["agent_aid"])
                         for step in workflow}
            ok = run_ma_task(task_def["name"], task_def["task"], workflow,
                             orchestrator, receivers, ctx.xmss)
            reset_agent_contexts(ctx.all_agents)
            if not ok:
                break
    finally:
        teardown_phase(ctx)


def run(two_agent_tasks, ma_tasks):
    """Run the phases config.json enables against the given scenario."""
    banner("MAGIQ")
    t0 = time.time()
    try:
        if CFG.get("run_phase_a", True):
            run_phase_a(two_agent_tasks)
        if CFG.get("run_phase_b", True):
            run_phase_b(ma_tasks)
    finally:
        banner("All phases complete")
        print(f"\n  Wall time: {time.time() - t0:.1f}s")


def main():
    import demo
    run(demo.TWO_AGENT_TASKS, demo.MA_TASKS)


if __name__ == "__main__":
    main()
