"""
AFEM Schemas — public API
=========================
Re-exports all schema types from the sub-modules so callers can write:

    from schemas import EmailRecord, ToolCallEvent, IntegrityReport

Sub-module responsibilities
---------------------------
``schemas.email``
    Mailbox data models: EmailRecord, DraftRecord, SearchResult.
    Consumed by the agent tool layer.

``schemas.evidence``
    Forensic event models: SessionStartEvent, ToolCallEvent, etc.
    Consumed by the collector and all forensic pipeline phases.

``schemas.integrity``
    Integrity layer types: FindingType, Severity, ForensicFinding,
    EvidenceTrust, VerificationResult, IntegrityReport, HashChainRecord.
    Consumed by Phase 2 (Integrity) and all later phases (3–5).
"""
from __future__ import annotations

# Mailbox data models
from schemas.email import (
    DraftRecord,
    EmailRecord,
    SearchResult,
)

# Forensic event types
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

# Integrity layer types (Phase 2+)
from schemas.integrity import (
    EvidenceTrust,
    FINDING_SEVERITY,
    FindingType,
    ForensicFinding,
    HashChainRecord,
    IntegrityReport,
    Severity,
    VerificationResult,
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
    # Integrity layer types
    "FindingType",
    "Severity",
    "FINDING_SEVERITY",
    "ForensicFinding",
    "EvidenceTrust",
    "HashChainRecord",
    "VerificationResult",
    "IntegrityReport",
]