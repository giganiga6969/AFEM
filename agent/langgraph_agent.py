"""
AFEM LangGraph Email Agent
==========================
A minimal ReAct-style agent that:

1. Accepts a natural-language user prompt.
2. Invokes email tools against mailbox.db as the LLM directs.
3. Logs every observable event to ``data/evidence/evidence.jsonl`` via
   ``EvidenceCollector``.
4. Returns the agent's final text response to the caller.

Research framing
----------------
The agent is *not* the research contribution. It is a controlled testbed that
generates realistic autonomous-action traces for the AFEM forensic pipeline.
Keep it as simple as possible: every line of complexity here is a line not
in the forensic pipeline.

Graph structure
---------------
    START → agent_node ──calls LLM──► has tool calls? ─Yes─► tool_node ─┐
                 ▲                                                        │
                 └────────────────────────────────────────────────────────┘
                          No (final response) → END

State
-----
``AgentState`` is a ``TypedDict`` carrying:
- ``messages``   : full LangChain message history (merged by ``add_messages``)
- ``session_id`` : UUID string for this run
- ``collector``  : live ``EvidenceCollector`` instance — not serialised by
                   LangGraph; stored as a plain Python object reference
- ``iteration``  : safety counter for the ``MAX_ITERATIONS`` guard

Evidence integration
--------------------
Evidence is logged at exactly two points:

- ``agent_node``: logs ``ToolCallEvent`` for each tool the LLM decided to
  call, or ``AgentResponseEvent`` when the LLM emits a final text response.

- ``tool_node``:  logs ``ToolResultEvent`` after each tool returns.

This captures both the agent's *intent* (what it decided to do) and the
*outcome* (what actually happened), which are the two pieces of information
Phase 3 attribution requires.

LLM client
----------
``_LLM`` is built once at module import time with tools already bound.
Rebuilding it on every ``agent_node`` call wastes initialisation overhead and
produces misleading profiling numbers when benchmarking the forensic pipeline.
"""
from __future__ import annotations

from datetime import time
import json
import logging
from urllib import response
import uuid
from pathlib import Path
from typing import Annotated, Any, Optional

from langchain_core import messages
from langchain_ollama import ChatOllama
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.tools import tool as lc_tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict

from collector import EvidenceCollector
from config import LLM_MODEL, MAX_ITERATIONS
from agent.tools import create_draft, retrieve_email, search_email, send_email

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt — loaded once at module import
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_PATH = Path(__file__).parent / "prompts" / "system_prompt.txt"
_SYSTEM_PROMPT: str = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------------------
# LangChain tool wrappers
#
# These thin functions are the only coupling point between LangChain's tool
# protocol and the pure Python tool implementations in agent/tools/.
#
# The name argument to @lc_tool sets what the LLM sees and must exactly
# match a ToolName enum value so the collector can coerce it without error.
# ---------------------------------------------------------------------------


@lc_tool("search_email")
def lc_search_email(keyword: str, limit: int = 10) -> str:
    """
    Search emails by keyword.

    Returns lightweight search results containing:
    - id
    - sender
    - subject
    - date
    - snippet

    The snippet is only a preview.

    If the complete email contents are required,
    call retrieve_email(id).

    Do not assume the snippet contains the full email.
    """

    # Prevent excessively large search results
    limit = max(1, min(limit, 5))

    results = search_email(keyword, limit)

    return json.dumps(
        {
            "count": len(results),
            "results": [r.model_dump() for r in results],
        },
        indent=2,
    )


@lc_tool("retrieve_email")
def lc_retrieve_email(identifier: str) -> str:
    """
    Retrieve a single email by its integer id or Message-ID header value.
    Pass a numeric string (e.g. '42') for id lookup, or a Message-ID string
    (e.g. '<payroll-q2@enron.com>') for header lookup.
    """
    parsed: int | str = identifier
    try:
        parsed = int(identifier)
    except ValueError:
        pass
    result = retrieve_email(parsed)
    if result is None:
        return json.dumps({"error": f"No email found for identifier={identifier!r}"})
    return json.dumps(result.model_dump())


@lc_tool("create_draft")
def lc_create_draft(
    sender:     str,
    recipients: str,
    subject:    str,
    body:       str,
    cc:         str = "",
) -> str:
    """Create a new draft email and store it in the mailbox. Returns the draft record as JSON."""
    record = create_draft(
        sender=sender,
        recipients=recipients,
        subject=subject,
        body=body,
        cc=cc if cc else None,
    )
    return json.dumps(record.model_dump())


@lc_tool("send_email")
def lc_send_email(draft_id: str) -> str:
    """Send a previously created draft email. Pass its integer id as a string."""
    try:
        record = send_email(int(draft_id))
        return json.dumps(record.model_dump())
    except ValueError as exc:
        return json.dumps({"error": str(exc)})


# Build tool list and lookup dict once at module level.
_LC_TOOLS     = [lc_search_email, lc_retrieve_email, lc_create_draft, lc_send_email]
_TOOL_BY_NAME = {t.name: t for t in _LC_TOOLS}

# Build LLM client once — not inside agent_node, which runs on every loop.
_LLM = ChatOllama(
    model=LLM_MODEL,
    temperature=0,
    reasoning=False,
).bind_tools(_LC_TOOLS)


# ---------------------------------------------------------------------------
# Agent state
# ---------------------------------------------------------------------------


class AgentState(TypedDict):
    messages:   Annotated[list[BaseMessage], add_messages]
    session_id: str
    collector:  Any   # EvidenceCollector — runtime object, not serialised by LangGraph
    iteration:  int


# ---------------------------------------------------------------------------
# Evidence helper
# ---------------------------------------------------------------------------


def _get_collector(state: AgentState) -> EvidenceCollector:
    """
    Retrieve the collector from state with an explicit type annotation.

    Centralising this access means that if the collector is ever moved to a
    different state key or wrapped, only this function needs updating.
    """
    return state["collector"]  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

def _build_artifact_references(tool_name: str, result_obj: dict) -> dict:
    """
    Convert tool output into lightweight forensic references.

    mailbox.db remains the authoritative evidence source.
    JSONL stores only references to those artifacts.
    """

    if tool_name == "search_email":
        results = result_obj.get("results", [])

        return {
            "row_count": result_obj.get("count", len(results)),
            "evidence_refs": [
                {
                    "artifact_type": "email",
                    "artifact_id": email["id"],
                }
                for email in results
            ],
        }

    elif tool_name == "retrieve_email":
        return {
            "artifact_type": "email",
            "artifact_id": result_obj["id"],
            "message_id": result_obj["message_id"],
            "content_hash": result_obj["content_hash"],
        }

    return result_obj



def agent_node(state: AgentState) -> dict:
    """
    Invoke the LLM and log what it decided to do.

    If the LLM emits tool calls → log one ``ToolCallEvent`` per call and
    return the ``AIMessage`` for ``tool_node`` to execute.

    If the LLM emits a text response → log ``AgentResponseEvent`` and
    route to END.
    """
    collector = _get_collector(state)
    iteration = state.get("iteration", 0)

    messages  = [SystemMessage(content=_SYSTEM_PROMPT)] + state["messages"]
    logger.info("=== Calling LLM ===")

    import time

    logger.info("Calling LLM...")

    start = time.perf_counter()

    response: AIMessage = _LLM.invoke(messages)

    elapsed = time.perf_counter() - start

    logger.info("LLM completed in %.2f seconds", elapsed)

    logger.info("=== LLM Returned ===")
    logger.info("Content:\n%s", response.content)
    logger.info("Tool calls:\n%s", response.tool_calls)

    if response.tool_calls:
        for tc in response.tool_calls:
            collector.log_tool_call(
                tool_name=tc["name"],
                input_data=tc["args"],
            )
    else:
        collector.log_agent_response(content=response.content or "")

    return {
        "messages":  [response],
        "iteration": iteration + 1,
    }


def tool_node(state: AgentState) -> dict:
    """
    Execute every pending tool call and log each result.

    Returns a ``ToolMessage`` per call so the LLM can see the outcomes on
    its next iteration.
    """
    collector     = _get_collector(state)
    last_message: AIMessage = state["messages"][-1]
    tool_messages: list[ToolMessage] = []

    for tc in last_message.tool_calls:
        tool_name = tc["name"]
        tool_args = tc["args"]
        tool_id   = tc["id"]

        lc_fn = _TOOL_BY_NAME.get(tool_name)
        if lc_fn is None:
            error_msg = f"Unknown tool requested by agent: {tool_name!r}"
            logger.error(error_msg)
            collector.log_tool_result(
                tool_name=tool_name,
                output_data=None,
                error=error_msg,
            )
            tool_messages.append(ToolMessage(
                content=json.dumps({"error": error_msg}),
                tool_call_id=tool_id,
            ))
            continue

        try:
            result_str: str = lc_fn.invoke(tool_args)
            result_obj      = json.loads(result_str)

            row_count: Optional[int] = None
            if isinstance(result_obj, dict) and "count" in result_obj:
                row_count = result_obj["count"]

            collector.log_tool_result(
                tool_name=tool_name,
                output_data=_build_artifact_references(tool_name, result_obj),
                row_count=row_count,
            )
            tool_messages.append(ToolMessage(
                content=result_str,
                tool_call_id=tool_id,
            ))
            logger.info("Tool completed.  name=%s  row_count=%s", tool_name, row_count)

        except Exception as exc:
            error_msg = str(exc)
            logger.exception("Tool raised exception.  name=%s  error=%s", tool_name, error_msg)
            collector.log_tool_result(
                tool_name=tool_name,
                output_data=None,
                error=error_msg,
            )
            tool_messages.append(ToolMessage(
                content=json.dumps({"error": error_msg}),
                tool_call_id=tool_id,
            ))

    return {"messages": tool_messages}


def _should_continue(state: AgentState) -> str:
    """
    Routing function: send to ``tool_node`` if the last ``AIMessage``
    contains tool calls; route to END otherwise.

    The ``MAX_ITERATIONS`` guard prevents infinite loops if the LLM keeps
    requesting tool calls without converging. In practice this should not
    trigger for the email task domain, but it protects against prompt
    injection attacks that could try to loop the agent indefinitely.
    """
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and last.tool_calls:
        if state.get("iteration", 0) >= MAX_ITERATIONS:
            logger.warning(
                "MAX_ITERATIONS (%d) reached — forcing END to prevent infinite loop.",
                MAX_ITERATIONS,
            )
            return END
        return "tool_node"
    return END


# ---------------------------------------------------------------------------
# Graph construction (executed once at module import)
# ---------------------------------------------------------------------------


def _build_graph() -> Any:
    graph = StateGraph(AgentState)
    graph.add_node("agent_node", agent_node)
    graph.add_node("tool_node",  tool_node)
    graph.set_entry_point("agent_node")
    graph.add_conditional_edges("agent_node", _should_continue, {
        "tool_node": "tool_node",
        END: END,
    })
    graph.add_edge("tool_node", "agent_node")
    return graph.compile()


_GRAPH = _build_graph()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_agent(user_prompt: str, session_id: Optional[str] = None) -> str:
    """
    Run one complete agent session for the given prompt.

    Parameters
    ----------
    user_prompt :
        Natural-language instruction for the email agent.
    session_id :
        Optional UUID string. A new UUID is generated if not supplied,
        which is the normal case for production use. Supplying a fixed
        value is useful in tests that need to query ``evidence.jsonl`` by id.

    Returns
    -------
    str
        The agent's final natural-language response.
    """
    if session_id is None:
        session_id = str(uuid.uuid4())

    collector = EvidenceCollector(session_id=session_id)
    collector.log_session_start(
    user_prompt=user_prompt,
    model=LLM_MODEL,
    )
    collector.log_user_prompt(content=user_prompt)

    initial_state: AgentState = {
        "messages":   [HumanMessage(content=user_prompt)],
        "session_id": session_id,
        "collector":  collector,
        "iteration":  0,
    }

    status     = "completed"
    final_text = ""

    try:
        final_state = _GRAPH.invoke(initial_state)

        # The last AIMessage without tool_calls holds the final answer.
        for msg in reversed(final_state["messages"]):
            if isinstance(msg, AIMessage) and not msg.tool_calls:
                final_text = msg.content or ""
                break

    except Exception as exc:
        logger.exception("Agent session failed.  session=%s  error=%s", session_id, exc)
        final_text = f"[Agent error: {exc}]"
        status     = "error"
        collector.log_agent_response(content=final_text)

    finally:
        collector.log_session_end(status=status)

    return final_text