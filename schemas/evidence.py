"""
AFEM Forensic Event Schemas
============================
Pydantic v2 models that define the structure of every forensic event written
to ``data/evidence/evidence.jsonl``.

All collector, agent, and future AFEM modules (integrity, attribution,
reconstruction, reporting) import from here — never from each other —
ensuring a stable, version-controlled data contract.

Separation of concerns
-----------------------
This file contains **only** forensic event types.
Mailbox data models (``EmailRecord``, ``DraftRecord``) live in
``schemas/email.py`` and are consumed by the agent tool layer, not by the
forensic pipeline.

Event hierarchy
---------------
BaseEvent               (session_id, sequence_number, timestamp, event_type)
  ├─ SessionStartEvent  (user_prompt, model)
  ├─ UserPromptEvent    (content)
  ├─ ToolCallEvent      (tool_name: ToolName, input_data)
  ├─ ToolResultEvent    (tool_name: ToolName, output_data, error, row_count)
  ├─ AgentResponseEvent (content)
  └─ SessionEndEvent    (total_events, status)

``sequence_number``
-------------------
The per-session ordinal position of the event (0-based), assigned by
``EvidenceCollector._write()`` at write time. It allows Phase 2 integrity
code to detect gaps or reordering in the JSONL file without parsing
timestamps, which can collide when multiple events occur within the same
millisecond.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """The six event types emitted by the AFEM evidence collector."""

    SESSION_START  = "session_start"
    USER_PROMPT    = "user_prompt"
    TOOL_CALL      = "tool_call"
    TOOL_RESULT    = "tool_result"
    AGENT_RESPONSE = "agent_response"
    SESSION_END    = "session_end"


class ToolName(str, Enum):
    """
    The four tools available to the LangGraph email agent.

    Typed as a ``str`` subclass so values serialise as plain strings in JSON
    (e.g. ``"search_email"`` rather than ``"ToolName.search_email"``).

    Using an enum here rather than a bare string means:
    - Phase 3 attribution code can match on ``ToolName`` exhaustively.
    - New tools added to the agent must be registered here first, making
      the schema the canonical record of the agent's capabilities.
    - Unregistered tool names are rejected at the collector boundary, not
      silently written to the evidence file.
    """

    RETRIEVE_EMAIL = "retrieve_email"
    SEARCH_EMAIL   = "search_email"
    CREATE_DRAFT   = "create_draft"
    SEND_EMAIL     = "send_email"


# ---------------------------------------------------------------------------
# Base event
# ---------------------------------------------------------------------------


class BaseEvent(BaseModel):
    """
    Fields present on every forensic event.

    ``sequence_number`` is the zero-based position of this event within its
    session, assigned by ``EvidenceCollector._write()``. It is separate from
    the JSONL file line number so that evidence from multiple sessions can be
    stored in a single file for bulk analysis without ambiguity.
    """

    session_id:      str = Field(..., description="UUID identifying the agent session")
    sequence_number: int = Field(
        default=0,
        description="Zero-based ordinal position of this event within the session",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of when this event was recorded",
    )
    event_type: EventType

    model_config = {"use_enum_values": True}

    def to_jsonl(self) -> str:
        """Serialise to a single-line JSON string with no trailing newline."""
        return json.dumps(self.model_dump(), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Concrete event types
# ---------------------------------------------------------------------------


class SessionStartEvent(BaseEvent):
    """
    First event in every session. Records the initiating prompt and the
    model used, giving Phase 3 attribution a fixed session anchor point.
    """

    event_type:  EventType = EventType.SESSION_START
    user_prompt: str = Field(..., description="The user prompt that initiated this session")
    model:       str = Field(..., description="LLM model identifier (e.g. claude-sonnet-4-6)")


class UserPromptEvent(BaseEvent):
    """
    Records the raw user input as the first substantive evidence event.

    Distinct from ``SessionStartEvent`` because future multi-turn sessions
    may emit multiple ``UserPromptEvent`` entries within a single session,
    whereas ``SessionStartEvent`` is always exactly one per session.
    """

    event_type: EventType = EventType.USER_PROMPT
    content:    str = Field(..., description="Raw user prompt text")


class ToolCallEvent(BaseEvent):
    """
    Records the agent's *intent* to call a tool, captured before the tool
    executes.

    ``tool_name`` is typed as ``ToolName`` to ensure only registered tools
    appear in the evidence file.

    Pairing each ``ToolCallEvent`` with its subsequent ``ToolResultEvent``
    (matched by ``session_id`` + ``sequence_number + 1``) is the fundamental
    operation of Phase 3 attribution.
    """

    event_type: EventType = EventType.TOOL_CALL
    tool_name:  ToolName  = Field(..., description="The tool the agent decided to invoke")
    input_data: dict[str, Any] = Field(
        default_factory=dict,
        description="The arguments passed to the tool, as supplied by the LLM",
    )


class ToolResultEvent(BaseEvent):
    """
    Records the *outcome* of a tool call. Logged immediately after the tool
    returns, before the LLM sees the result.

    ``error`` is non-null when the tool raised an exception. In that case
    ``output_data`` is ``None``. Both fields are always present in the JSON
    output (as ``null``) to simplify downstream parsing.
    """

    event_type:  EventType     = EventType.TOOL_RESULT
    tool_name:   ToolName      = Field(..., description="The tool that produced this result")
    output_data: Any           = Field(default=None, description="Serialisable tool output")
    error:       Optional[str] = Field(default=None, description="Exception message if the tool failed")
    row_count:   Optional[int] = Field(
        default=None,
        description="Number of email records returned; None for non-retrieval tools",
    )


class AgentResponseEvent(BaseEvent):
    """
    Records the agent's final natural-language response to the user.
    This is the last substantive event before ``SessionEndEvent``.
    """

    event_type: EventType = EventType.AGENT_RESPONSE
    content:    str = Field(..., description="The agent's final response text")


class SessionEndEvent(BaseEvent):
    """
    Final event in every session.

    ``total_events`` is the count of all events logged *before* this one,
    enabling integrity checks: a reader that counts JSONL lines for a
    ``session_id`` and finds a different number than ``total_events`` knows
    the file has been truncated or corrupted.
    """

    event_type:   EventType = EventType.SESSION_END
    total_events: int = Field(
        ...,
        description="Count of events logged before this SessionEndEvent",
    )
    status: str = Field(
        default="completed",
        description="Session outcome: 'completed' | 'error' | 'interrupted'",
    )