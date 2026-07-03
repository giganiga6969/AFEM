"""
AFEM Schemas — public API
=========================
Re-exports all schema types from the two sub-modules so callers can write:

    from schemas import EmailRecord, ToolCallEvent, EventType

without needing to know which sub-module each type lives in.

Sub-module responsibilities
---------------------------
``schemas.email``
    Mailbox data models (``EmailRecord``, ``DraftRecord``).
    Consumed by the agent tool layer.

``schemas.evidence``
    Forensic event models (``SessionStartEvent``, ``ToolCallEvent``, …).
    Consumed by the collector and all future forensic pipeline phases.
"""
from __future__ import annotations

from schemas.email import DraftRecord, EmailRecord, SearchResult
from schemas.evidence import (
    AgentResponseEvent,
    BaseEvent,
    EventType,
    SessionEndEvent,
    SessionStartEvent,
    ToolCallEvent,
    ToolName,
    ToolResultEvent,
    UserPromptEvent,
)

__all__ = [
    # Mailbox data models
    "EmailRecord",
    "DraftRecord",
    "SearchResult",
    # Forensic event types
    "EventType",
    "ToolName",
    "BaseEvent",
    "SessionStartEvent",
    "UserPromptEvent",
    "ToolCallEvent",
    "ToolResultEvent",
    "AgentResponseEvent",
    "SessionEndEvent",
]