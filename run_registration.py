"""
run_registration.py - Phase orchestration for Saga+ demo.

Recreated file with both Phase A (two-agent) and Phase B (multi-agent)
workflows after accidental deletion.
"""

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



#  Task definitions

TASK_SCHEDULING = (
    "Find a 30-minute slot on Tuesday 2025-04-22 where Bob and Alice are both "
    "free to discuss the NDSS submission."
)

TASK_EXPENSE = (
    "Prepare a NeurIPS expense summary by checking inbox receipts and combining "
    "verified items only."
)

TASK_WRITING = (
    "Let's collaborate on a blog post about the privacy implications of AI. "
    "Start by reading your own blog posts for background and share your key "
    "perspective plus a short draft section."
)

TWO_AGENT_TASKS = [
    ("Task 1 - Calendar Scheduling", TASK_SCHEDULING),
    ("Task 2 - NeurIPS Expense Report", TASK_EXPENSE),
    ("Task 3 - AI Privacy Blog Post", TASK_WRITING),
]


TASK_MA_SCHEDULING = (
    "Find a 30-minute slot on Tuesday 2025-04-22 where Bob, Alice, and Mallory "
    "are all free to discuss the NDSS submission. You are Bob's agent (the "
    "orchestrator). Talk to Alice's agent to collect her free slots, then talk to "
    "Mallory's agent (passing Alice's slots) to find a three-way overlap. Once "
    "all three can attend the same 30-minute window, schedule the meeting and "
    "emit <TASK_FINISHED>."
)

MA_WORKFLOW_SCHEDULING = [
    {
        "agent_aid": "alice@domain.com:agent-alpha",
        "instruction": (
            "You are Alice's agent. Bob is coordinating a three-way meeting on "
            "Tuesday 2025-04-22. Check Alice's calendar and share her free "
            "30-minute slots. When Bob proposes a concrete slot, verify Alice "
            "is free and only then agree."
        ),
    },
    {
        "agent_aid": "mallory@domain.com:agent-gamma",
        "instruction": (
            "You are Mallory's agent. Bob is coordinating a three-way meeting "
            "on Tuesday 2025-04-22 and has already collected Alice's free slots. "
            "Check Mallory's calendar, share her free slots, and find a "
            "30-minute window that overlaps with Alice's. Once all three agree, "
            "confirm."
        ),
    },
]

TASK_MA_EXPENSE = (
    "Coordinate a combined three-way NeurIPS expense report (03-01 to 03-03, "
    "New Orleans). You are Bob's agent (the orchestrator). First talk to Alice's "
    "agent to collect her trip expenses and email ID. Then talk to Mallory's "
    "agent: share Alice's list, ask Mallory for hers, and only use "
    "receiver-provided expense data from the current step (no assumptions or "
    "invented values). and submit a single combined expense report covering all "
    "three of you. Emit <TASK_FINISHED> when the combined report is submitted."
)

MA_WORKFLOW_EXPENSE = [
    {
        "agent_aid": "alice@domain.com:agent-alpha",
        "instruction": (
            "You are Alice's agent. Bob is collecting NeurIPS trip expenses "
            "(03-01 to 03-03, New Orleans). Check Alice's inbox for trip-related "
            "expenses (hotel, travel, food, registration, etc.) and share the "
            "full itemised list along with Alice's email ID. Bob must rely only "
            "on the data you provide in this exchange."
        ),
    },
    {
        "agent_aid": "mallory@domain.com:agent-gamma",
        "instruction": (
            "You are Mallory's agent. Bob has already collected Alice's NeurIPS "
            "expenses. Check Mallory's inbox for her trip expenses and share the "
            "list plus her email ID. Bob will only use data explicitly provided "
            "in this exchange and verified carried context from the prior step. "
            "then submit one combined expense report for all three participants."
        ),
    },
]

TASK_MA_WRITING = (
    "Coordinate a collaborative three-way blog post on the privacy implications "
    "of AI. You are Bob's agent (the orchestrator). First talk to Alice's agent to "
    "gather her perspective and draft, then talk to Mallory's agent: share "
    "Alice's material, get Mallory's, and together agree on a unified final "
    "text. When all three perspectives are merged and agreed upon, save the "
    "final text as 'MA_AI_Privacy_Blog_Post.md' and emit <TASK_FINISHED>."
)

MA_WORKFLOW_WRITING = [
    {
        "agent_aid": "alice@domain.com:agent-alpha",
        "instruction": (
            "You are Alice's agent. Bob is coordinating a three-way blog post on "
            "AI and privacy. Read Alice's existing blog posts, share her key "
            "perspective, and contribute one self-contained draft section to Bob. "
            "Once you have shared both the perspective and draft section, "
            "explicitly end your next reply with <TASK_FINISHED>."
        ),
    },
    {
        "agent_aid": "mallory@domain.com:agent-gamma",
        "instruction": (
            "You are Mallory's agent. Bob has already gathered Alice's perspective "
            "and draft. Read Mallory's own blog posts, share her perspective with "
            "Bob, and provide one self-contained draft section. Then collaborate "
            "to combine all three viewpoints into the final unified blog post. "
            "When the combined text is agreed, explicitly end your confirming "
            "reply with <TASK_FINISHED>."
        ),
    },
]

MA_TASKS = [
    {"name": "MA Task 1 - Calendar Scheduling",
     "task": TASK_MA_SCHEDULING, "workflow": MA_WORKFLOW_SCHEDULING},
    {"name": "MA Task 2 - NeurIPS Expense Report",
     "task": TASK_MA_EXPENSE, "workflow": MA_WORKFLOW_EXPENSE},
    {"name": "MA Task 3 - AI Privacy Blog Post",
     "task": TASK_MA_WRITING, "workflow": MA_WORKFLOW_WRITING},
]



#  Phase context + setup/teardown

PhaseContext = namedtuple(
    "PhaseContext",
    "users all_agents xmss ca prov tls_client tls_server tls_paths",
)


def _load_user_files():
    pattern = os.path.join(ROOT_DIR, CFG["paths"]["data_users"], "*.json")
    items = []
    for f in sorted(glob.glob(pattern)):
        with open(f) as fh:
            items.append(json.load(fh))
    return items


def setup_phase(agent_cls, label):
    """Stand up a complete phase: CA, Provider, PQ-TLS, registered users and agents."""
    banner(f"{label}: Initialise")
    xmss = XMSSWrapper()
    ca = CertificateAuthority()
    if hasattr(ca, "init_keys"):
        ca.init_keys()

    prov = Provider(xmss)
    if hasattr(prov, "init_keys"):
        prov.init_keys(ca)

    tls_paths = generate_tls_certs(certs_dir("tls"))
    tls_server = TLSServer(tls_paths, prov.handle_request)
    tls_server.start()
    tls_client = TLSClient(tls_paths)

    users = {}
    all_agents = []
    user_defs = _load_user_files()
    for ud in user_defs:
        u = User(
            user_data=ud,
            xmss=xmss,
            tls_client=tls_client,
            tls_paths=tls_paths,
            agent_cls=agent_cls,
        )
        users[ud["uid"]] = u
        u.register(ca)
        u.register_agents(ca)
        all_agents.extend(list(u.agents.values()))

    return PhaseContext(
        users=users,
        all_agents=all_agents,
        xmss=xmss,
        ca=ca,
        prov=prov,
        tls_client=tls_client,
        tls_server=tls_server,
        tls_paths=tls_paths,
    )


def attach_llms(all_agents):
    model_client = load_model_client(os.path.join(SCRIPT_DIR, "llm.yaml"))
    for ag in all_agents:
        if hasattr(ag, "attach_llm"):
            ag.attach_llm(model_client)


def clear_all_agent_contexts(all_agents):
    """Hard reset model context and counters at task boundaries."""
    for ag in all_agents:
        if getattr(ag, "_app_agent", None):
            try:
                ag._app_agent.reset()
            except Exception:
                pass
        ag._llm_total_calls = 0
        ag._llm_total_sec = 0.0
        if hasattr(ag, "_llm_by_label"):
            ag._llm_by_label.clear()


def teardown_phase(ctx):
    for ag in ctx.all_agents:
        if hasattr(ag, "close_llm"):
            ag.close_llm()
        if hasattr(ag, "stop_listener"):
            ag.stop_listener()
    if getattr(ctx, "tls_server", None):
        ctx.tls_server.stop()
    try:
        ctx.xmss.cleanup()
    except Exception:
        pass
    time.sleep(0.3)



#  Phase A - two-agent

def _run_two_agent_task(task_name, task, initiator, receiver, xmss):
    banner(task_name)

    if getattr(initiator, "_app_agent", None):
        initiator._app_agent.reset()
    if getattr(receiver, "_app_agent", None):
        receiver._app_agent.reset()

    rx_result = {}
    rx_thread = threading.Thread(target=receiver.run_receiver_loop, args=(rx_result,), daemon=True)
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


def run_phase_a():
    ctx = setup_phase(Agent, "PHASE A (two-agent)")
    try:
        attach_llms(ctx.all_agents)
        bob = ctx.users["bob@domain.com"].agents["bob@domain.com:agent-beta"]
        alice = ctx.users["alice@domain.com"].agents["alice@domain.com:agent-alpha"]
        bob._xmss = ctx.xmss
        alice._xmss = ctx.xmss

        for task_name, task in TWO_AGENT_TASKS:
            ok = _run_two_agent_task(task_name, task, bob, alice, ctx.xmss)
            clear_all_agent_contexts(ctx.all_agents)
            if not ok:
                break
    finally:
        teardown_phase(ctx)


#  Phase B - multi-agent

def _build_ma_receivers(users, workflow):
    return {
        step["agent_aid"]: users[step["agent_aid"].split(":")[0]].agents[step["agent_aid"]]
        for step in workflow
    }


def _run_ma_agent_task(task_name, task, workflow, orchestrator, receivers, xmss):
    banner(task_name)
    print(f"\n[TASK] {task}\n")
    try:
        banner("(i) User-Agent Interaction (orchestrator: bob)")
        orchestrator.run_user_agent_interaction(task, workflow, xmss)

        banner("(ii) Inter-Agent Communication")
        phase_bw = orchestrator.run_workflow(workflow, receivers, xmss)

        banner(f"{task_name} Summary")
        print_llm_summary(
            "Multi-Agent LLM Cost",
            [orchestrator] + list(receivers.values()),
            role_fn=lambda a: "orchestrator" if a is orchestrator else "receiver",
        )
        print_bandwidth_summary("Multi-Agent Session Totals (orchestrator perspective)", phase_bw)

        return len(phase_bw) == len(workflow)
    finally:
        if hasattr(orchestrator, "cleanup_task"):
            orchestrator.cleanup_task(receivers)


def run_phase_b():
    ctx = setup_phase(AgentMA, "PHASE B (multi-agent)")
    try:
        attach_llms(ctx.all_agents)
        for ag in ctx.all_agents:
            ag._xmss = ctx.xmss
        orchestrator = ctx.users["bob@domain.com"].agents["bob@domain.com:agent-beta"]

        for task_def in MA_TASKS:
            task_name = task_def["name"]
            task = task_def["task"]
            workflow = task_def["workflow"]
            receivers = _build_ma_receivers(ctx.users, workflow)
            ok = _run_ma_agent_task(task_name, task, workflow, orchestrator, receivers, ctx.xmss)
            clear_all_agent_contexts(ctx.all_agents)
            if not ok:
                break
    finally:
        teardown_phase(ctx)


#  Entry point
def main():
    banner("Post-Quantum Saga+ Demo")

    run_a = CFG.get("run_phase_a", True)
    run_b = CFG.get("run_phase_b", True)

    t0 = time.time()
    try:
        if run_a:
            run_phase_a()
        if run_b:
            run_phase_b()
    finally:
        banner("All phases complete")
        print(f"\n  Wall time: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
