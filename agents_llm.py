import asyncio
import concurrent.futures
import os
import re
from typing import List, Union

import yaml
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.messages import TextMessage
from autogen_core import CancellationToken
from autogen_core.models import UserMessage
from autogen_ext.models.openai import OpenAIChatCompletionClient

from lib.common import ROOT_DIR

TASK_FINISHED = "<TASK_FINISHED>"

OUTPUT_DIR = os.path.join(ROOT_DIR, "output")


def load_model_client(yaml_path: str) -> OpenAIChatCompletionClient:
    """Build an OpenAI-compatible chat client from a YAML config file."""
    with open(yaml_path) as f:
        cfg = yaml.safe_load(f)

    model = cfg["model"]
    api_key = cfg.get("api_key") or os.getenv(
        cfg.get("api_key_env", "OPENAI_API_KEY"), "EMPTY")
    kwargs = {"model": model, "api_key": api_key}

    base_url = cfg.get("api_base") or cfg.get("base_url")
    if base_url:
        kwargs["base_url"] = base_url

    model_info = cfg.get("model_info")
    if model_info:
        kwargs["model_info"] = model_info
    elif "/" in model:
        kwargs["model_info"] = {
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": "unknown",
            "structured_output": False,
        }

    return OpenAIChatCompletionClient(**kwargs)


def _llm_call(model_client, prompt: str, timeout: int = 60) -> str:
    """Run a single-turn LLM call in a fresh thread and event loop."""

    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                model_client.create([UserMessage(content=prompt, source="user")]))
            content = result.content
            return content if isinstance(content, str) else str(content)
        finally:
            loop.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(run).result(timeout=timeout)

_AVAILABILITY_PERSONAS = {
    "bob@domain.com": (
        "a researcher who is busy 11:00-16:00 with back-to-back teaching, "
        "lab sessions, and supervision meetings. "
        "Free windows: early morning 9:00-11:00, a short lunch slot 12:30-13:00, "
        "and late afternoon 16:00-17:00."
    ),
    "alice@domain.com": (
        "a faculty member with morning lectures and committee work until 14:00, "
        "and an evening faculty meeting starting at 17:00. "
        "Free windows: afternoon 14:00-17:00, with 16:00-16:30 reliably open."
    ),
    "mallory@domain.com": (
        "a postdoc with a writing block every morning (9:00-12:00) and "
        "afternoon experiments (12:00-15:30). "
        "Free windows: 15:30-17:00, with 16:00-16:30 consistently free."
    ),
    "carol@domain.com": (
        "a PhD student with lab rotations (9:00-12:00) and a reading group "
        "(13:00-15:00). "
        "Free windows: 12:00-12:30, 15:00-15:30, and 16:00-17:00."
    ),
    "dave@domain.com": (
        "a systems engineer with a standup at 9:30, code-review blocks "
        "(10:00-13:00), and on-call duty (13:30-16:00). "
        "Free windows: 9:00-9:30, 13:00-13:30, and 16:00-17:30."
    ),
    "erin@domain.com": (
        "a visiting researcher with seminars (10:00-12:00) and student "
        "meetings (14:00-16:00). "
        "Free windows: 9:00-10:00, 12:00-13:00, and 16:00-16:45."
    ),
}


def _calendar_tools(user_email: str, model_client=None):
    events: List[dict] = []

    def check_availability(day: str) -> str:
        """Return free time windows for this user on the given day."""
        if model_client is None:
            return f"{user_email} is free on {day}: 10:00-11:00, 14:00-15:30"
        persona = _AVAILABILITY_PERSONAS.get(
            user_email, "a researcher with a typical academic schedule")
        slots = _llm_call(model_client, (
            f"You are a calendar assistant for {user_email}, who is {persona}. "
            f"List their realistically free 30-minute slots on {day} based on "
            f"the schedule described above. Return only a comma-separated list "
            f"of time ranges, for example '9:00-9:30, 14:00-14:30'. "
            f"No explanation, just the time ranges."))
        return f"{user_email} is free on {day}: {slots}"

    def schedule_meeting(title: str, day: str, time_slot: str,
                         participants: str) -> str:
        """Create a calendar event and send invites to comma-separated people."""
        events.append({"title": title, "day": day,
                       "time": time_slot, "participants": participants})
        return (f"Meeting '{title}' scheduled on {day} at {time_slot}. "
                f"Invite sent to: {participants}.")

    return [check_availability, schedule_meeting]


def _email_tools(user_email: str, model_client=None):
    outbox: List[dict] = []
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    def check_inbox() -> str:
        """Return expense-related emails from the recent NeurIPS trip."""
        if model_client is None:
            return f"{user_email} inbox: (no expenses found)"
        snapshot = _llm_call(model_client, (
            f"You are an email assistant for {user_email}. "
            f"Generate a realistic inbox snapshot containing expense-related "
            f"emails from a recent NeurIPS conference trip to New Orleans "
            f"(03-01 to 03-03). Include realistic items such as hotel, travel, "
            f"food and registration fees with dollar amounts. Return a concise "
            f"list only, no explanation."))
        return f"{user_email} inbox:\n{snapshot}"

    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email and return a confirmation."""
        outbox.append({"to": to, "subject": subject, "body": body})
        return f"Email sent to {to} (subject: {subject!r})"

    def submit_expense_report(trip: str, total: float, items: str,
                              participants: str) -> str:
        """Submit a combined expense report for a trip."""
        filename = "MA_NeurIPS_Expense_Report.txt"
        with open(os.path.join(OUTPUT_DIR, filename), "w",
                  encoding="utf-8") as f:
            f.write(f"Trip: {trip}\n"
                    f"Participants: {participants}\n"
                    f"Total: ${total:.2f}\n"
                    f"Items:\n{items}\n")
        return (f"Expense report for '{trip}' submitted successfully. "
                f"Total: ${total:.2f}. Saved to {filename}.")

    return [check_inbox, send_email, submit_expense_report]


def _writing_tools(user_email: str, model_client=None):
    docs: dict = {}

    def read_blog_posts() -> str:
        """Return this user's existing blog posts on AI and privacy."""
        if model_client is None:
            return f"No existing blog posts found for {user_email}."
        return _llm_call(model_client, (
            f"Write a 2-3 paragraph blog post about the privacy implications "
            f"of AI, from the perspective of {user_email}. Write in first "
            f"person. Be specific and opinionated about a concrete privacy "
            f"concern."))

    def create_document(title: str, content: str) -> str:
        """Create or overwrite a document by title."""
        docs[title] = content
        # basename() keeps a model-supplied title from escaping OUTPUT_DIR.
        safe_title = os.path.basename(title)
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(os.path.join(OUTPUT_DIR, safe_title), "w",
                  encoding="utf-8") as f:
            f.write(content)
        return f"Document '{safe_title}' saved ({len(content)} chars)"

    def list_documents() -> str:
        """List all documents created so far."""
        return ", ".join(docs.keys()) or "no documents yet"

    return [read_blog_posts, create_document, list_documents]


TOOLS = {
    "calendar": _calendar_tools,
    "email": _email_tools,
    "writing": _writing_tools,
}

SYSTEM_PROMPT = (
    "You are {name}, an AI agent for user {user_email}.\n"
    "Your available tools are: {tool}. You ONLY have these tools, do not "
    "claim to have or use any other tools. Always call a tool to perform an "
    "action, do not just describe what you would do.\n"
    "\n"
    "Coordination protocol, follow this order strictly:\n"
    "  1. Use your own tools to gather YOUR information first, for example "
    "check your own availability, read your own inbox, read your own blog "
    "posts, and share it with the peer.\n"
    "  2. Ask the peer for their corresponding information.\n"
    "  3. Compare and agree on a joint outcome such as a time slot, combined "
    "data or draft content.\n"
    "  4. Only after BOTH sides have confirmed the details, take the final "
    "action (schedule_meeting / submit_expense_report / create_document).\n"
    "NEVER schedule, submit, or save anything before step 4.\n"
    "Never invent peer-specific facts such as availability, expenses or draft "
    "content. Only use peer facts that were explicitly provided by the peer in "
    "the current conversation or supplied as verified context by the system.\n"
    "\n"
    "Scheduling rules, which apply when negotiating a meeting time:\n"
    "  - You must call check_availability BEFORE stating your own free slots, "
    "even on your very first message. Never claim to be free at any time "
    "without running the tool first, and do not assume or copy the peer's "
    "times.\n"
    "  - Before accepting ANY time proposed by your peer, call "
    "check_availability again to confirm that specific slot is in your free "
    "windows. Never accept based on memory or assumption.\n"
    "  - If the proposed time is NOT in your free slots, say so explicitly and "
    "propose a specific counter-slot from your actual free windows. Never just "
    "say you are busy, always offer a concrete alternative.\n"
    "  - Keep negotiating: if each counter-proposal fails, call "
    "check_availability each time and propose the next available option until "
    "a mutual slot is found.\n"
    "  - Only confirm a time after personally verifying it via the tool. Both "
    "sides must explicitly agree on the same slot before scheduling.\n"
    "\n"
    "Reply concisely, 1-3 sentences per turn. Deliberate on your response "
    "before submitting. Only emit the exact token {finished} after the final "
    "action has been successfully carried out. Do not emit {finished} "
    "prematurely."
)


def _normalise_tools(tool_field: Union[str, List[str], None]) -> List[str]:
    """Return a validated list of tool-category names."""
    if tool_field is None:
        return []
    if isinstance(tool_field, str):
        names = list(TOOLS.keys()) if tool_field == "all" else [tool_field]
    else:
        names = list(tool_field)
    unknown = [n for n in names if n not in TOOLS]
    if unknown:
        raise ValueError(f"Unknown tool(s) {unknown}. Choose from {list(TOOLS)}")
    return names


class AppAgent:
    """An AssistantAgent bound to one or more tool categories."""

    def __init__(self, name: str, user_email: str,
                 tool_name: Union[str, List[str]],
                 model_client: OpenAIChatCompletionClient):
        names = _normalise_tools(tool_name)
        if not names:
            raise ValueError("At least one tool must be specified")

        self.name = name
        self.user_email = user_email
        self.tool_name = names

        tools = []
        for n in names:
            tools.extend(TOOLS[n](user_email, model_client=model_client))

        safe = (name.replace(":", "_").replace("@", "_at_")
                    .replace(".", "_").replace("-", "_"))

        reflect = os.getenv("REFLECT_ON_TOOL_USE", "1") not in ("0", "false", "False")
        self._agent = AssistantAgent(
            name=safe,
            model_client=model_client,
            tools=tools,
            system_message=SYSTEM_PROMPT.format(
                name=name, user_email=user_email,
                tool=", ".join(names), finished=TASK_FINISHED),
            reflect_on_tool_use=reflect,
        )
        self._loop = asyncio.new_event_loop()

    def reply(self, text: str) -> str:
        result = self._loop.run_until_complete(
            self._agent.on_messages([TextMessage(content=text, source="peer")],
                                    CancellationToken()))
        return result.chat_message.content

    def reset(self):
        """Clear conversation history before starting a new task."""
        self._loop.run_until_complete(self._agent.on_reset(CancellationToken()))

    def close(self):
        try:
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True))
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.close()
        except Exception:
            pass


def task_is_finished(text: str) -> bool:
    return bool(re.search(r"<\s*task[\s_]*finished\s*>", text or "",
                          re.IGNORECASE))
