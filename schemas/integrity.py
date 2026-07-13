"""
AFEM Integrity Schemas
======================
Pydantic models for Phase 2: Evidence Integrity Manager.

All integrity-layer types live here so that Phases 3–5 import a single
module rather than scattering integrity types across the codebase.

Module contents
---------------
FindingType     Structured enum identifying the category of each anomaly.
                Phase 3–5 consume this instead of parsing free-text strings.

Severity        Risk level of a finding (LOW / MEDIUM / HIGH / CRITICAL).

ForensicFinding One structured anomaly, combining FindingType, Severity,
                a human-readable message, and the affected event number.
                Replaces free-text tamper_evidence strings as the primary
                machine-readable output of the verifier.

EvidenceTrust   Session-level trust verdict consumed by Phase 3 (Timeline)
                and Phase 4 (Attribution) to gate or annotate their outputs.

VerificationResult  Per-event outcome. Extended with finding_type and
                    severity so Phase 5 can render per-event annotations
                    without re-running verification.

IntegrityReport Top-level verifier output. Extended with verified_at,
                evidence_trust, first_failure_type, session_complete,
                workflow_anomalies, and findings so every downstream phase
                can consume the report directly.

Design decisions
----------------
Backward compatibility
    Every new field carries a default value (None, [], or an enum default).
    Code that constructs IntegrityReport or VerificationResult with only
    the original positional fields continues to work without modification.

Free-text tamper_evidence preserved
    tamper_evidence (List[str]) is retained alongside findings (List[ForensicFinding])
    for human-readable display in the CLI and investigation reports.
    Machine-readable code uses findings; human-readable output uses tamper_evidence.

EvidenceTrust mapping
    TRUSTED         chain_valid=True, session_complete=True, no anomalies
    DEGRADED        chain_valid=True but workflow anomalies or incomplete session
    COMPROMISED     chain_valid=False (any hash failure)
    UNKNOWN         verifier could not determine trust (corrupted file)

Phase pipeline contract
-----------------------
Phase 3 (Timeline Reconstruction) consumes:
    IntegrityReport.evidence_trust      — gate: skip COMPROMISED sessions
    IntegrityReport.session_complete    — gate: partial reconstruction flag
    VerificationResult.is_valid         — annotate timeline nodes

Phase 4 (Explainable Attribution) consumes:
    IntegrityReport.evidence_trust      — confidence weight on attributions
    IntegrityReport.workflow_anomalies  — additional attribution signals
    IntegrityReport.first_failure_type  — fast-path for highly compromised sessions

Phase 5 (Investigation Report Generation) consumes:
    IntegrityReport.verified_at         — report header timestamp
    IntegrityReport.evidence_trust      — trust assessment section
    IntegrityReport.findings            — structured finding list for templates
    IntegrityReport.tamper_evidence     — human-readable narrative
    IntegrityReport.verdict             — section header (VERIFIED / FAILED)
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# FindingType — structured anomaly categories
# ---------------------------------------------------------------------------


class FindingType(str, Enum):
    """
    Structured category for every integrity anomaly.

    Using a typed enum rather than free-text strings allows Phase 3–5
    to branch on finding type without parsing human-readable messages.

    Values are lowercase strings so they serialise readably in JSON evidence
    files and investigation reports.
    """

    # Hash-chain failures
    CONTENT_HASH_MISMATCH = "content_hash_mismatch"
    """event_hash recomputed from event content does not match stored value.
    Primary indicator of event payload modification after sealing."""

    CHAIN_LINK_MISMATCH = "chain_link_mismatch"
    """previous_hash does not match the prior event's event_hash.
    Indicates deletion, insertion, or reordering of events before this one."""

    # Sequence anomalies
    SEQUENCE_GAP = "sequence_gap"
    """One or more sequence numbers are missing.
    Strong indicator of event deletion."""

    DUPLICATE_SEQUENCE = "duplicate_sequence"
    """The same sequence number appears more than once.
    Indicates event insertion or file corruption."""

    # Session structural problems
    TRUNCATED_SESSION = "truncated_session"
    """SessionEndEvent is present but total_events does not match actual count,
    or the session file has fewer events than SessionEndEvent declares."""

    MISSING_END_EVENT = "missing_end_event"
    """No SessionEndEvent found. Session may have been interrupted or truncated."""

    TOTAL_EVENTS_MISMATCH = "total_events_mismatch"
    """SessionEndEvent.total_events field does not match the number of events
    found before it in the session file."""

    # Field-level problems
    MISSING_FIELD = "missing_field"
    """A mandatory forensic field (session_id, sequence_number, timestamp,
    event_type, previous_hash, or event_hash) is absent from an event."""

    # Multi-session contamination
    SESSION_MISMATCH = "session_mismatch"
    """More than one session_id found in the same JSONL file.
    Indicates file concatenation error or deliberate contamination."""

    # Temporal anomalies
    TIMESTAMP_ANOMALY = "timestamp_anomaly"
    """Event timestamps are non-monotonic (later event has earlier timestamp).
    May indicate log reordering or clock manipulation."""

    # Event workflow violations
    WORKFLOW_ANOMALY = "workflow_anomaly"
    """Events appear in an order that violates the expected AFEM workflow.
    Examples: session_start not first; session_end not last; tool_call without
    a following tool_result; duplicate session_start."""

    # File-level problems
    CORRUPTED_JSON = "corrupted_json"
    """One or more lines in the JSONL file are not valid JSON.
    Indicates file corruption or partial write."""


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """
    Risk level of a forensic finding.

    Used by Phase 5 to categorise findings in investigation reports and by
    Phase 4 to weight attribution confidence.

    LOW       Informational anomaly; does not by itself compromise evidence.
    MEDIUM    Suspicious anomaly that requires investigator attention.
    HIGH      Strong indicator of tampering; significantly reduces trust.
    CRITICAL  Definitive evidence of tampering or corruption.
    """

    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# Severity defaults for each FindingType — used by the verifier when
# constructing ForensicFinding objects so severity is never arbitrary.
FINDING_SEVERITY: dict[FindingType, Severity] = {
    FindingType.CONTENT_HASH_MISMATCH:  Severity.CRITICAL,
    FindingType.CHAIN_LINK_MISMATCH:    Severity.CRITICAL,
    FindingType.SEQUENCE_GAP:           Severity.HIGH,
    FindingType.DUPLICATE_SEQUENCE:     Severity.HIGH,
    FindingType.TRUNCATED_SESSION:      Severity.HIGH,
    FindingType.MISSING_END_EVENT:      Severity.MEDIUM,
    FindingType.TOTAL_EVENTS_MISMATCH:  Severity.HIGH,
    FindingType.MISSING_FIELD:          Severity.HIGH,
    FindingType.SESSION_MISMATCH:       Severity.CRITICAL,
    FindingType.TIMESTAMP_ANOMALY:      Severity.MEDIUM,
    FindingType.WORKFLOW_ANOMALY:       Severity.MEDIUM,
    FindingType.CORRUPTED_JSON:         Severity.HIGH,
}


# ---------------------------------------------------------------------------
# EvidenceTrust
# ---------------------------------------------------------------------------


class EvidenceTrust(str, Enum):
    """
    Session-level trust verdict derived from the full IntegrityReport.

    Consumed by Phase 3 (Timeline Reconstruction) and Phase 4 (Attribution)
    to gate or annotate their outputs without re-running verification.

    TRUSTED      Chain intact, session complete, no anomalies of any kind.
    DEGRADED     Chain intact but session is incomplete or has workflow
                 anomalies. Reconstruction is possible but partial.
    COMPROMISED  One or more hash failures. Evidence cannot be fully trusted.
    UNKNOWN      Verifier encountered an unrecoverable error (corrupted file,
                 missing fields). Trust level cannot be determined.
    """

    TRUSTED     = "trusted"
    DEGRADED    = "degraded"
    COMPROMISED = "compromised"
    UNKNOWN     = "unknown"


# ---------------------------------------------------------------------------
# ForensicFinding
# ---------------------------------------------------------------------------


class ForensicFinding(BaseModel):
    """
    One structured integrity anomaly detected during verification.

    Replaces free-text tamper_evidence strings as the primary machine-readable
    output for Phases 3–5. Human-readable message is also included so the CLI
    and investigation reports can display it directly.

    Attributes
    ----------
    finding_type :
        Structured category. Phases 3–5 branch on this, never on message text.
    severity :
        Risk level. Phase 4 uses this to weight attribution confidence.
        Phase 5 uses this to categorise findings in report sections.
    affected_sequence :
        sequence_number of the event where the anomaly was detected, or None
        for session-level findings (e.g. MISSING_END_EVENT, SESSION_MISMATCH).
    message :
        Human-readable description. Suitable for display in the CLI and in
        the Findings section of the investigation report.
    """

    finding_type:       FindingType
    severity:           Severity
    affected_sequence:  Optional[int] = Field(
        default=None,
        description="sequence_number of the affected event; None for session-level findings.",
    )
    message: str = Field(
        ...,
        description="Human-readable description of the finding.",
    )


# ---------------------------------------------------------------------------
# HashChainRecord
# ---------------------------------------------------------------------------


class HashChainRecord(BaseModel):
    """
    Minimal view of one sealed JSONL line used during verification.

    Not a subclass of BaseEvent because the verifier must be able to process
    sealed lines even if new event types are added in future phases, without
    requiring schema updates here.
    """

    session_id:      str
    sequence_number: int
    event_type:      str
    previous_hash:   str = Field(
        ...,
        description=(
            "SHA-256 hex digest of the previous event's canonical JSON; "
            "'0' * 64 for the genesis event."
        ),
    )
    event_hash: str = Field(
        ...,
        description=(
            "SHA-256 hex digest of this event's canonical JSON "
            "(which includes previous_hash)."
        ),
    )


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


class VerificationResult(BaseModel):
    """
    Per-event outcome from the chain verifier.

    Extended with finding_type and severity so Phase 5 can render per-event
    chain map annotations without re-running verification.

    is_valid is True only when:
    - All mandatory fields are present.
    - previous_hash matches the prior event's event_hash (or GENESIS_HASH).
    - Recomputing SHA-256 over this line's canonical JSON reproduces event_hash.
    """

    sequence_number:  int
    event_type:       str
    is_valid:         bool
    expected_prev:    str = Field(
        ..., description="The hash the verifier expected as previous_hash."
    )
    actual_prev:      str = Field(
        ..., description="The previous_hash value found in the file."
    )
    expected_hash:    str = Field(
        ..., description="The event_hash the verifier recomputed from content."
    )
    actual_hash:      str = Field(
        ..., description="The event_hash value found in the file."
    )
    # --- extended fields (all have defaults for backward compatibility) ---
    failure_reason:   Optional[str] = Field(
        default=None,
        description="Human-readable reason for failure; None when is_valid is True.",
    )
    finding_type:     Optional[FindingType] = Field(
        default=None,
        description=(
            "Structured failure category; None when is_valid is True. "
            "If both CONTENT_HASH_MISMATCH and CHAIN_LINK_MISMATCH apply, "
            "CONTENT_HASH_MISMATCH takes precedence as the more specific finding."
        ),
    )
    severity:         Optional[Severity] = Field(
        default=None,
        description="Risk level derived from finding_type; None when is_valid is True.",
    )


# ---------------------------------------------------------------------------
# IntegrityReport
# ---------------------------------------------------------------------------


class IntegrityReport(BaseModel):
    """
    Complete integrity verification report for one session.

    This is the primary output of Phase 2 and the primary input to
    Phases 3, 4, and 5. Every downstream phase consumes this report
    directly — no phase should re-run verification or parse human-readable
    strings from tamper_evidence.

    Original fields (Phase 2 baseline)
    -----------------------------------
    session_id, total_events, chain_valid, first_broken_seq,
    events, tamper_evidence, genesis_hash, terminal_hash

    Extended fields (Phase 2 hardening — all have defaults)
    ---------------------------------------------------------
    verified_at         ISO-8601 UTC timestamp of when verification ran.
                        Phase 5 includes this in the report header.

    evidence_trust      EvidenceTrust verdict. Phase 3 and 4 use this to
                        gate reconstruction and attribution.

    session_complete    True if a valid SessionEndEvent was found with a
                        matching total_events count. Phase 3 uses this to
                        flag partial reconstruction.

    first_failure_type  FindingType of the first detected anomaly, or None
                        if chain_valid is True. Phase 4 uses this to
                        fast-path highly compromised sessions.

    workflow_anomalies  List of human-readable workflow violation descriptions.
                        Phase 4 uses these as additional attribution signals.

    findings            List[ForensicFinding] — structured findings replacing
                        tamper_evidence for machine consumption. Phase 5
                        uses this to populate structured report sections.

    Backward compatibility
    ----------------------
    All extended fields have default values. Code that constructs
    IntegrityReport with only the original fields continues to work.
    """

    # --- original fields ---
    session_id:        str
    total_events:      int
    chain_valid:       bool
    first_broken_seq:  Optional[int] = Field(
        default=None,
        description=(
            "sequence_number of the first event where the chain breaks; "
            "None when chain_valid is True."
        ),
    )
    events:            List[VerificationResult]
    tamper_evidence:   List[str] = Field(
        default_factory=list,
        description=(
            "Human-readable list of detected anomalies. "
            "Retained for CLI display and investigation report narratives. "
            "Machine-readable code should consume 'findings' instead."
        ),
    )
    genesis_hash:      str = Field(
        ...,
        description="event_hash of the first (sequence_number=0) event.",
    )
    terminal_hash:     str = Field(
        ...,
        description="event_hash of the last event in the file.",
    )

    # --- extended fields ---
    verified_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description=(
            "ISO-8601 UTC timestamp of when verification was performed. "
            "Phase 5 includes this in the investigation report header."
        ),
    )
    evidence_trust: EvidenceTrust = Field(
        default=EvidenceTrust.UNKNOWN,
        description=(
            "Session-level trust verdict. "
            "Phase 3 uses this to gate timeline reconstruction. "
            "Phase 4 uses this to weight attribution confidence."
        ),
    )
    session_complete: bool = Field(
        default=False,
        description=(
            "True if a valid SessionEndEvent was found with a total_events "
            "count matching the actual number of preceding events. "
            "Phase 3 uses this to flag partial vs. complete reconstruction."
        ),
    )
    first_failure_type: Optional[FindingType] = Field(
        default=None,
        description=(
            "FindingType of the first anomaly detected, or None if chain_valid "
            "is True and no structural anomalies were found. "
            "Phase 4 uses this to fast-path attribution on compromised sessions."
        ),
    )
    workflow_anomalies: List[str] = Field(
        default_factory=list,
        description=(
            "Human-readable descriptions of event workflow violations "
            "(e.g. session_start not first, tool_call without tool_result). "
            "Phase 4 uses these as additional attribution signals."
        ),
    )
    findings: List[ForensicFinding] = Field(
        default_factory=list,
        description=(
            "Structured list of all forensic findings from this verification. "
            "Phase 5 consumes this list directly to populate report sections "
            "without parsing tamper_evidence strings."
        ),
    )

    # --- computed properties ---

    @property
    def verdict(self) -> str:
        """Single-word summary suitable for report headers: VERIFIED or FAILED."""
        return "VERIFIED" if self.chain_valid else "FAILED"

    @property
    def has_critical_findings(self) -> bool:
        """True if any finding has CRITICAL severity. Phase 4 convenience accessor."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def critical_finding_count(self) -> int:
        """Count of CRITICAL findings. Phase 5 report summary convenience accessor."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def highest_severity(self) -> Optional[Severity]:
        """
        The most severe finding in this report, or None if findings is empty.

        Severity order: CRITICAL > HIGH > MEDIUM > LOW.
        Phase 5 uses this to colour-code the report summary.
        """
        if not self.findings:
            return None
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max(self.findings, key=lambda f: order.index(f.severity)).severity