"""
Two-agent:   {"name", "task", "initiator", "receiver"}
Multi-agent: {"name", "task", "orchestrator", "workflow"}
             workflow is a list of {"agent_aid", "instruction"} in contact order
"""

ORCHESTRATOR = "bob@domain.com:agent-beta"

# Bob orchestrates, and the order below defines the static workflow.
RECEIVERS = [
    ("alice@domain.com:agent-alpha", "Alice"),
    ("mallory@domain.com:agent-gamma", "Mallory"),
    ("carol@domain.com:agent-delta", "Carol"),
    ("dave@domain.com:agent-epsilon", "Dave"),
    ("erin@domain.com:agent-zeta", "Erin"),
]

_NAMES = [name for _, name in RECEIVERS]
_ALL = ", ".join(["Bob"] + _NAMES[:-1]) + f", and {_NAMES[-1]}"
_N = len(RECEIVERS) + 1


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
    {"name": "Task 1 - Calendar Scheduling",
     "task": TASK_SCHEDULING,
     "initiator": ORCHESTRATOR,
     "receiver": "alice@domain.com:agent-alpha"},
    {"name": "Task 2 - NeurIPS Expense Report",
     "task": TASK_EXPENSE,
     "initiator": ORCHESTRATOR,
     "receiver": "alice@domain.com:agent-alpha"},
    {"name": "Task 3 - AI Privacy Blog Post",
     "task": TASK_WRITING,
     "initiator": ORCHESTRATOR,
     "receiver": "alice@domain.com:agent-alpha"},
]


# The orchestrator's model never sees the overall TASK_MA_* string, because
# AgentMA._build_step_task() composes each step's prompt from the receiver
# instruction plus the carried handoff. Anything aimed at the orchestrator
# therefore has to travel inside `instruction`, which is what these rules do.
_FINAL_RULE = {
    "calendar": (
        " COORDINATOR RULE (this is the final step): before proposing any time, "
        "write out each participant's confirmed free slots from the verified "
        "carried context, add your own, and compute the intersection across all "
        f"{_N} participants. Propose ONLY a window that appears in every one of "
        f"the {_N} lists. Do not propose a slot merely because it is free for "
        "you and this receiver. If no window is common to all, say so "
        "explicitly instead of scheduling. Once this receiver confirms the "
        "common window, call schedule_meeting with all "
        f"{_N} participants, then emit <TASK_FINISHED>."
    ),
    "expense": (
        " COORDINATOR RULE (this is the final step): collect every "
        "participant's itemised expenses from the verified carried context, "
        "add this receiver's and your own, then call submit_expense_report "
        f"exactly once with all {_N} participants, the complete item list, and "
        "the arithmetic total of every amount. Only after the tool returns "
        "successfully, emit <TASK_FINISHED>."
    ),
    "writing": (
        " COORDINATOR RULE (this is the final step): merge every participant's "
        "perspective and draft from the verified carried context with this "
        "receiver's and your own into one unified blog post, then call "
        "create_document with title 'MA_AI_Privacy_Blog_Post.md' and the full "
        "merged text. Only after the tool returns successfully, emit "
        "<TASK_FINISHED>."
    ),
}


def _workflow(instruction_fn, kind):
    """Build a t-step static workflow, one step per receiving agent."""
    last = len(RECEIVERS) - 1
    return [{"agent_aid": aid,
             "instruction": instruction_fn(i, name)
                            + (_FINAL_RULE[kind] if i == last else "")}
            for i, (aid, name) in enumerate(RECEIVERS)]


TASK_MA_SCHEDULING = (
    f"Find a 30-minute slot on Tuesday 2025-04-22 where {_ALL} are all free "
    f"to discuss the NDSS submission. You are Bob's agent (the orchestrator). "
    f"Talk to each of the {len(RECEIVERS)} other agents in turn, collecting "
    f"their free slots and carrying forward every set of slots you have already "
    f"gathered. Only a window that every one of the {_N} participants has "
    f"confirmed counts as a valid answer. Once you have a {_N}-way overlap, "
    f"schedule the meeting with schedule_meeting and emit <TASK_FINISHED>."
)

WORKFLOW_SCHEDULING = _workflow(lambda i, name: (
    f"You are {name}'s agent. Bob is coordinating a {_N}-way meeting on "
    f"Tuesday 2025-04-22. Check {name}'s calendar with check_availability and "
    f"share {name}'s free 30-minute slots. "
    + ("Bob has already collected slots from earlier participants and will "
       "share them, so narrow down to windows that work for everyone. "
       if i else "")
    + f"When Bob proposes a concrete slot, call check_availability again to "
      f"verify {name} is free and only then agree. Do NOT emit <TASK_FINISHED> "
      f"yourself, only Bob decides when the overall task is complete."
), "calendar")


TASK_MA_EXPENSE = (
    f"Coordinate a combined NeurIPS expense report for all {_N} participants "
    f"({_ALL}) covering 03-01 to 03-03 in New Orleans. You are Bob's agent "
    f"(the orchestrator). Talk to each of the {len(RECEIVERS)} other agents "
    f"in turn to collect their itemised expenses and email IDs, carrying "
    f"forward everything already gathered. Use only receiver-provided data "
    f"from this conversation, with no assumptions or invented values. Also "
    f"check your own inbox for Bob's expenses. When you have all {_N} sets, "
    f"call submit_expense_report exactly once with the full itemised list, the "
    f"arithmetic total, and all {_N} participants, then emit <TASK_FINISHED>."
)

WORKFLOW_EXPENSE = _workflow(lambda i, name: (
    f"You are {name}'s agent. Bob is collecting NeurIPS trip expenses. "
    f"Call check_inbox once and reply with {name}'s expense items and amounts "
    f"and {name}'s email ID. Keep it to a short list. "
    + ("Bob has already collected expenses from earlier participants. "
       if i else "")
    + "Bob will rely only on data explicitly provided in this exchange and on "
      "verified carried context from prior steps. Do NOT emit <TASK_FINISHED> "
      "yourself, only Bob decides when the overall task is complete."
), "expense")


TASK_MA_WRITING = (
    f"Coordinate a collaborative blog post on the privacy implications of AI "
    f"with all {_N} participants ({_ALL}). You are Bob's agent (the "
    f"orchestrator). Talk to each of the {len(RECEIVERS)} other agents in "
    f"turn to gather their perspective and draft section, carrying forward "
    f"everything already gathered. Read your own blog posts for Bob's "
    f"contribution. When all {_N} perspectives are collected, merge them into "
    f"one unified text and call create_document with the title "
    f"'MA_AI_Privacy_Blog_Post.md' and the full merged text, then emit "
    f"<TASK_FINISHED>."
)

WORKFLOW_WRITING = _workflow(lambda i, name: (
    f"You are {name}'s agent. Bob is collecting material for a blog post on "
    f"AI and privacy. Call read_blog_posts once and reply with {name}'s key "
    f"perspective in one sentence plus a short draft paragraph. "
    + ("Bob has already gathered perspectives from earlier participants. "
       if i else "")
    + "Share your perspective and draft section, then answer any follow-up "
      "questions Bob asks. Do NOT emit <TASK_FINISHED> yourself, only Bob "
      "decides when the overall task is complete."
), "writing")


MA_TASKS = [
    {"name": "MA Task 1 - Calendar Scheduling",
     "task": TASK_MA_SCHEDULING,
     "orchestrator": ORCHESTRATOR,
     "workflow": WORKFLOW_SCHEDULING},
    {"name": "MA Task 2 - NeurIPS Expense Report",
     "task": TASK_MA_EXPENSE,
     "orchestrator": ORCHESTRATOR,
     "workflow": WORKFLOW_EXPENSE},
    {"name": "MA Task 3 - AI Privacy Blog Post",
     "task": TASK_MA_WRITING,
     "orchestrator": ORCHESTRATOR,
     "workflow": WORKFLOW_WRITING},
]
