"""
AFEM Report Schemas — Phase 3: Timeline Reconstruction
=======================================================
Pydantic models for the Timeline Reconstruction output.

All downstream phases (4 and 5) consume ``TimelineReport`` directly.
No later phase re-parses JSONL or re-runs integrity verification.

Design decisions
-----------------
TimelineEntry
    One reconstructed action in the timeline. Maps directly onto one or two
    JSONL events (e.g. a tool_call + tool_result pair collapses into one
    entry). Fields are named for forensic semantics rather than raw event
    field names, so Phase 5 can render them into a report narrative without
    transformation.

    ``integrity_status``  propagated per-entry from IntegrityReport.events so
    Phase 5 can annotate compromised entries in the report without re-running
    verification.

ReconstructionCompleteness
    Enum describing how much of the session could be reconstructed.
    Phase 4 uses this to weight attribution confidence.

TimelineReport
    Top-level output of Phase 3. Primary input to Phases 4 and 5.
    Contains the full ordered timeline, metadata about the reconstruction
    quality, and a direct reference to the upstream IntegrityReport so
    Phase 5 can include the integrity section without loading it separately.

Phase pipeline contract
-----------------------
Phase 4 (Attribution) reads:
    TimelineReport.entries              — action sequence for rule matching
    TimelineReport.completeness         — confidence weight
    TimelineReport.integrity_report     — trust propagation
    TimelineEntry.event_type            — event classification
    TimelineEntry.tool_name             — tool sequence analysis
    TimelineEntry.integrity_status      — per-entry trust

Phase 5 (Report Generation) reads:
    TimelineReport.session_id           — case header
    TimelineReport.reconstructed_at     — report timestamp
    TimelineReport.entries              — timeline table
    TimelineReport.completeness         — reconstruction quality section
    TimelineReport.anomalies            — anomaly section
    TimelineReport.integrity_report     — integrity section
    TimelineReport.user_prompt          — case description
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ReconstructionCompleteness(str, Enum):
    """
    Describes how completely the session could be reconstructed.

    COMPLETE    All events present, session_start and session_end found,
                no sequence gaps, hash chain valid.
    PARTIAL     Some events reconstructed but gaps, missing session_end, or
                DEGRADED integrity means the picture is incomplete.
    MINIMAL     Only a fragment of events could be recovered (e.g. most events
                are corrupted or the session is severely truncated).
    FAILED      No meaningful reconstruction was possible.
    """
    COMPLETE = "complete"
    PARTIAL  = "partial"
    MINIMAL  = "minimal"
    FAILED   = "failed"


class TimelineEntry(BaseModel):
    """
    One forensically meaningful action in the reconstructed timeline.

    Mapping strategy
    ----------------
    - session_start    → one entry: actor=system, action=session_initiated
    - user_prompt      → one entry: actor=user,   action=prompt_submitted
    - tool_call        → paired with its tool_result into ONE entry so the
                         timeline reads as "agent invoked X and got Y"
    - agent_response   → one entry: actor=agent,  action=response_generated
    - session_end      → one entry: actor=system, action=session_terminated

    Unpaired tool_call (no following tool_result) → entry flagged with
    anomaly="orphaned_tool_call".

    Fields
    ------
    sequence_number
        Primary ordering key. Taken from the event with the lower
        sequence_number in a paired entry (i.e. the tool_call).
    timestamp
        ISO-8601 string from the event. The reconstructor uses
        sequence_number for ordering, not timestamp, but records
        timestamps as supporting temporal evidence for Phase 5.
    event_type
        The raw AFEM event_type string (session_start, tool_call, etc.).
        Paired tool_call/tool_result entries use event_type="tool_action".
    actor
        "user", "agent", or "system".
    action
        Human-readable description of what happened.
    tool_name
        Populated for tool_action entries; None for others.
        Phase 4 uses this for tool-sequence rule matching.
    artifact_refs
        List of artifact references from the ToolResult event, e.g.
        [{"artifact_type": "email", "artifact_id": 4}].
        Phase 4 uses these to assess what data the agent accessed.
    input_summary
        Short summary of tool input or prompt content.
        Kept brief: full content is in the raw JSONL.
    output_summary
        Short summary of tool output or agent response.
    integrity_status
        "valid", "invalid", or "unknown". Propagated from the corresponding
        VerificationResult.is_valid flags. Phase 5 uses this to annotate
        compromised entries in the report.
    anomaly
        Non-empty string describing any detected anomaly for this entry
        (e.g. "orphaned_tool_call", "integrity_failure", "missing_result").
        Empty string when no anomaly.
    raw_sequence_numbers
        List of the JSONL sequence_numbers that contributed to this entry.
        Allows Phase 5 to cross-reference back to the raw evidence file.
    """

    sequence_number:      int
    timestamp:            Optional[str]  = None
    event_type:           str
    actor:                str            = Field(..., description="user | agent | system")
    action:               str
    tool_name:            Optional[str]  = None
    artifact_refs:        List[Dict[str, Any]] = Field(default_factory=list)
    input_summary:        Optional[str]  = None
    output_summary:       Optional[str]  = None
    integrity_status:     str            = Field(
        default="unknown",
        description="valid | invalid | unknown — propagated from IntegrityReport",
    )
    anomaly:              str            = Field(
        default="",
        description="Non-empty when an anomaly exists for this entry.",
    )
    raw_sequence_numbers: List[int]      = Field(
        default_factory=list,
        description="JSONL sequence_numbers that contributed to this entry.",
    )


class TimelineReport(BaseModel):
    """
    Complete output of Phase 3: Timeline Reconstruction.

    Primary input to Phase 4 (Attribution) and Phase 5 (Report Generation).
    No later phase should re-run reconstruction or re-parse JSONL.

    The ``integrity_report`` field embeds the full IntegrityReport so that
    Phase 5 can include the integrity section in the investigation report
    without loading it separately.

    ``integrity_report`` is typed as ``Optional[Any]`` rather than
    ``Optional[IntegrityReport]`` to avoid a circular import dependency
    between schemas.report and schemas.integrity. At runtime it will
    always be an IntegrityReport instance. Phase 4 and 5 should import
    IntegrityReport from schemas.integrity to access typed fields.
    """

    session_id:       str
    reconstructed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of when reconstruction ran.",
    )
    user_prompt:      Optional[str] = Field(
        default=None,
        description="The original user prompt that initiated the session.",
    )
    entries:          List[TimelineEntry] = Field(
        default_factory=list,
        description="Ordered list of reconstructed timeline actions.",
    )
    completeness:     ReconstructionCompleteness = Field(
        default=ReconstructionCompleteness.FAILED,
        description=(
            "Quality of reconstruction. "
            "Phase 4 uses this to weight attribution confidence."
        ),
    )
    anomalies:        List[str] = Field(
        default_factory=list,
        description=(
            "Session-level anomalies detected during reconstruction "
            "(e.g. sequence gaps, orphaned tool calls, missing session end). "
            "Phase 5 includes these in the anomaly section of the report."
        ),
    )
    tool_sequence:    List[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of tool names called during the session. "
            "Phase 4 uses this for rule-based sequence matching."
        ),
    )
    integrity_report: Optional[Any] = Field(
        default=None,
        description=(
            "The IntegrityReport that was used as input to this reconstruction. "
            "Embedded here so Phase 5 does not need to reload it separately."
        ),
    )
    evidence_trust:   str = Field(
        default="unknown",
        description=(
            "EvidenceTrust value from the IntegrityReport, copied here as a "
            "plain string so Phase 4/5 can read it without importing "
            "schemas.integrity."
        ),
    )
    total_events_in_session:  int = Field(
        default=0,
        description="Total raw JSONL events in the session file.",
    )
    total_timeline_entries:   int = Field(
        default=0,
        description="Number of TimelineEntry objects produced.",
    )

    @property
    def is_trustworthy(self) -> bool:
        """
        True when evidence trust is TRUSTED or DEGRADED.
        Phase 4 uses this as a gate: COMPROMISED or UNKNOWN sessions still
        get an attribution result but with low confidence.
        """
        return self.evidence_trust in ("trusted", "degraded")

    @property
    def tool_calls_made(self) -> List[str]:
        """List of tool names used, in order. Convenience for Phase 4."""
        return [
            e.tool_name for e in self.entries
            if e.tool_name is not None
        ]
