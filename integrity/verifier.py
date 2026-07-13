"""
AFEM Integrity — Chain Verifier
================================
Verifies the SHA-256 hash chain of a sealed session JSONL file and produces
a structured IntegrityReport.

Public interface (unchanged from Phase 2 baseline)
---------------------------------------------------
    verify_session(session_path)        -> IntegrityReport
    verify_sessions_dir(sessions_dir)   -> list[IntegrityReport]

The verifier is stateless and read-only. It never writes to any file and
can safely be called concurrently on any number of sessions.

Validation checks performed
----------------------------
1.  Corrupted JSON detection
    Lines that are not valid JSON are recorded as CORRUPTED_JSON findings
    rather than crashing the verifier. Remaining valid lines are still
    verified.

2.  Mandatory field presence
    Every event must contain: session_id, sequence_number, timestamp,
    event_type. Sealed events must additionally contain previous_hash
    and event_hash. Absent fields produce MISSING_FIELD findings.

3.  Session ID consistency
    All events must share the same session_id. Multiple session IDs in
    one file produce a SESSION_MISMATCH finding.

4.  Sequence gap and duplicate detection
    Non-contiguous sequence numbers → SEQUENCE_GAP (HIGH).
    Duplicate sequence numbers → DUPLICATE_SEQUENCE (HIGH).

5.  Chain linkage verification
    previous_hash must equal the prior event's event_hash → CHAIN_LINK_MISMATCH
    (CRITICAL) on failure.

6.  Content hash verification
    Recomputed SHA-256 must match stored event_hash → CONTENT_HASH_MISMATCH
    (CRITICAL) on failure.

7.  SessionEndEvent presence
    Missing SessionEndEvent → MISSING_END_EVENT (MEDIUM).

8.  total_events cross-check
    SessionEndEvent.total_events must equal actual event count before it →
    TOTAL_EVENTS_MISMATCH (HIGH) or TRUNCATED_SESSION (HIGH).

9.  Event workflow validation
    - session_start must be first (sequence 0)
    - session_end must be last
    - No more than one session_start or session_end
    - Every tool_call must be followed by a tool_result
    Each violation → WORKFLOW_ANOMALY (MEDIUM).

10. Timestamp monotonicity
    Timestamps must be non-decreasing. Reversal → TIMESTAMP_ANOMALY (MEDIUM).

EvidenceTrust derivation
------------------------
COMPROMISED   any CRITICAL finding (hash failure or session mismatch)
DEGRADED      no CRITICAL findings but any HIGH/MEDIUM finding, or
              session_complete is False
TRUSTED       chain_valid=True, session_complete=True, no findings at all
UNKNOWN       set as default; only persists if an unrecoverable error
              prevents completing verification

Phase pipeline contract
-----------------------
Phase 3 (Timeline Reconstruction) reads:
    evidence_trust, session_complete, per-event is_valid

Phase 4 (Explainable Attribution) reads:
    evidence_trust, workflow_anomalies, first_failure_type, findings

Phase 5 (Investigation Report Generation) reads:
    verdict, verified_at, evidence_trust, findings, tamper_evidence,
    genesis_hash, terminal_hash, session_complete
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from integrity.hash_chain import GENESIS_HASH, compute_event_hash
from schemas.integrity import (
    EvidenceTrust,
    FindingType,
    FINDING_SEVERITY,
    ForensicFinding,
    IntegrityReport,
    Severity,
    VerificationResult,
)

logger = logging.getLogger(__name__)

# Mandatory fields every event must carry before hash-field validation.
_MANDATORY_FIELDS: frozenset[str] = frozenset({
    "session_id", "sequence_number", "timestamp", "event_type",
})

# Additional fields required in sealed events.
_SEAL_FIELDS: frozenset[str] = frozenset({"previous_hash", "event_hash"})

# Known workflow event types.
_SESSION_START = "session_start"
_SESSION_END   = "session_end"
_TOOL_CALL     = "tool_call"
_TOOL_RESULT   = "tool_result"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify_session(session_path: Path) -> IntegrityReport:
    """
    Verify the hash chain and structural integrity of one sealed session.

    Parameters
    ----------
    session_path :
        Path to a .jsonl file previously sealed by sealer.seal_session().

    Returns
    -------
    IntegrityReport
        Full verification report. chain_valid is True only if every event
        passes both the linkage and content hash checks. evidence_trust
        reflects the overall session trust level for Phase 3/4 consumption.

    Raises
    ------
    FileNotFoundError
        If session_path does not exist.
    ValueError
        If the file is empty or contains no parseable events at all.
    """
    if not session_path.exists():
        raise FileNotFoundError(f"Session file not found: {session_path}")

    # --- Parse JSONL, capturing corrupted lines as findings ---
    raw_events, corrupt_findings = _read_jsonl_tolerant(session_path)

    if not raw_events and not corrupt_findings:
        raise ValueError(f"Session file is empty: {session_path}")

    if not raw_events:
        # All lines were corrupted — build a minimal UNKNOWN report.
        return _build_unrecoverable_report(session_path, corrupt_findings)

    # --- Determine session_id from first parseable event ---
    session_id = raw_events[0].get("session_id", session_path.stem)

    # --- Accumulate findings and tamper_evidence in parallel ---
    findings:         list[ForensicFinding] = list(corrupt_findings)
    tamper_evidence:  list[str]             = [f.message for f in corrupt_findings]
    workflow_anomalies: list[str]           = []

    # --- Structural checks (order matters: run before chain verification) ---
    _check_mandatory_fields(raw_events, findings, tamper_evidence)
    _check_session_id_consistency(raw_events, session_id, findings, tamper_evidence)

    # Sort by sequence_number for all subsequent processing.
    sorted_evts = sorted(raw_events, key=lambda e: e.get("sequence_number", 0))

    _check_sequence_gaps(sorted_evts, findings, tamper_evidence)
    _check_workflow(sorted_evts, findings, tamper_evidence, workflow_anomalies)
    _check_timestamps(sorted_evts, findings, tamper_evidence)

    # --- Hash-chain verification ---
    results:      list[VerificationResult] = []
    first_broken: int | None              = None
    expected_prev = GENESIS_HASH

    for event in sorted_evts:
        result = _verify_one(event, expected_prev)
        results.append(result)

        if not result.is_valid and first_broken is None:
            first_broken = result.sequence_number
            tamper_evidence.append(result.failure_reason or "Unknown hash failure")
            if result.finding_type:
                findings.append(ForensicFinding(
                    finding_type      = result.finding_type,
                    severity          = result.severity or FINDING_SEVERITY[result.finding_type],
                    affected_sequence = result.sequence_number,
                    message           = result.failure_reason or "Hash verification failed",
                ))

        expected_prev = event.get("event_hash", GENESIS_HASH)

    chain_valid = first_broken is None

    # --- SessionEnd cross-check ---
    session_complete = _check_session_end(
        sorted_evts, findings, tamper_evidence
    )

    # --- Derive first_failure_type ---
    first_failure_type: FindingType | None = (
        findings[0].finding_type if findings else None
    )

    # --- Derive EvidenceTrust ---
    evidence_trust = _derive_trust(chain_valid, session_complete, findings)

    # --- Build report ---
    genesis_hash  = sorted_evts[0].get("event_hash",  "") if sorted_evts else ""
    terminal_hash = sorted_evts[-1].get("event_hash", "") if sorted_evts else ""

    report = IntegrityReport(
        session_id          = session_id,
        total_events        = len(results),
        chain_valid         = chain_valid,
        first_broken_seq    = first_broken,
        events              = results,
        tamper_evidence     = tamper_evidence,
        genesis_hash        = genesis_hash,
        terminal_hash       = terminal_hash,
        verified_at         = datetime.now(timezone.utc).isoformat(),
        evidence_trust      = evidence_trust,
        session_complete    = session_complete,
        first_failure_type  = first_failure_type,
        workflow_anomalies  = workflow_anomalies,
        findings            = findings,
    )

    _log_report(report, session_path)
    return report


def verify_sessions_dir(
    sessions_dir: Path,
    *,
    skip_errors: bool = False,
) -> list[IntegrityReport]:
    """
    Verify every .jsonl file in sessions_dir.

    Parameters
    ----------
    sessions_dir :
        Directory containing per-session .jsonl files.
    skip_errors :
        If True, log and skip sessions that raise exceptions (empty files,
        permission errors). If False, the first error propagates.

    Returns
    -------
    list[IntegrityReport]
        One report per verified session, in filename order.
    """
    if not sessions_dir.exists():
        raise FileNotFoundError(f"Sessions directory not found: {sessions_dir}")

    reports: list[IntegrityReport] = []
    for jl_path in sorted(sessions_dir.glob("*.jsonl")):
        try:
            reports.append(verify_session(jl_path))
        except Exception as exc:
            if skip_errors:
                logger.error("Skipping session %s — %s", jl_path.name, exc)
            else:
                raise

    failed = sum(1 for r in reports if not r.chain_valid)
    logger.info(
        "Directory verification complete.  dir=%s  total=%d  failed=%d",
        sessions_dir, len(reports), failed,
    )
    return reports


# ---------------------------------------------------------------------------
# JSONL reading with corruption tolerance
# ---------------------------------------------------------------------------


def _read_jsonl_tolerant(
    path: Path,
) -> tuple[list[dict[str, Any]], list[ForensicFinding]]:
    """
    Read all lines from a JSONL file.

    Returns a tuple of (valid_events, corrupt_findings). Corrupt lines are
    captured as CORRUPTED_JSON findings rather than raising an exception,
    so the verifier can still process the remaining valid lines.
    """
    valid:    list[dict[str, Any]]  = []
    corrupt:  list[ForensicFinding] = []

    with open(path, encoding="utf-8") as fh:
        for line_num, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                valid.append(json.loads(line))
            except json.JSONDecodeError as exc:
                msg = (
                    f"Line {line_num}: JSON parse error — {exc}. "
                    f"Content (first 80 chars): {line[:80]!r}"
                )
                corrupt.append(ForensicFinding(
                    finding_type      = FindingType.CORRUPTED_JSON,
                    severity          = FINDING_SEVERITY[FindingType.CORRUPTED_JSON],
                    affected_sequence = None,
                    message           = msg,
                ))

    return valid, corrupt


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------


def _check_mandatory_fields(
    events:         list[dict[str, Any]],
    findings:       list[ForensicFinding],
    tamper_evidence: list[str],
) -> None:
    """
    Verify that every event contains all mandatory fields.

    Missing base fields (session_id, sequence_number, timestamp, event_type)
    and missing seal fields (previous_hash, event_hash) are both reported as
    MISSING_FIELD but with distinct messages.
    """
    all_required = _MANDATORY_FIELDS | _SEAL_FIELDS

    for event in events:
        seq = event.get("sequence_number", "?")
        for field in all_required:
            if field not in event:
                msg = (
                    f"Event {seq}: mandatory field '{field}' is missing. "
                    f"File may be corrupted or was written by an older collector version."
                )
                findings.append(ForensicFinding(
                    finding_type      = FindingType.MISSING_FIELD,
                    severity          = FINDING_SEVERITY[FindingType.MISSING_FIELD],
                    affected_sequence = seq if isinstance(seq, int) else None,
                    message           = msg,
                ))
                tamper_evidence.append(msg)


def _check_session_id_consistency(
    events:          list[dict[str, Any]],
    expected_sid:    str,
    findings:        list[ForensicFinding],
    tamper_evidence: list[str],
) -> None:
    """
    Verify all events share the same session_id.

    A file containing events from multiple sessions is a SESSION_MISMATCH —
    either a file concatenation error or deliberate contamination.
    """
    foreign_ids: set[str] = set()

    for event in events:
        sid = event.get("session_id", "")
        if sid and sid != expected_sid:
            foreign_ids.add(sid)

    if foreign_ids:
        msg = (
            f"Multiple session_id values found in one file. "
            f"Expected '{expected_sid}'. "
            f"Also found: {sorted(foreign_ids)}. "
            f"Possible file concatenation error or deliberate contamination."
        )
        findings.append(ForensicFinding(
            finding_type      = FindingType.SESSION_MISMATCH,
            severity          = FINDING_SEVERITY[FindingType.SESSION_MISMATCH],
            affected_sequence = None,
            message           = msg,
        ))
        tamper_evidence.append(msg)


def _check_sequence_gaps(
    sorted_events:   list[dict[str, Any]],
    findings:        list[ForensicFinding],
    tamper_evidence: list[str],
) -> None:
    """
    Detect non-contiguous and duplicate sequence numbers.

    Gaps indicate deletion; duplicates indicate insertion or corruption.
    """
    seen:     set[int] = set()
    expected: int      = 0

    for event in sorted_events:
        seq = event.get("sequence_number")
        if seq is None:
            continue

        if seq in seen:
            msg = (
                f"Duplicate sequence_number {seq} — "
                f"possible event insertion or file corruption."
            )
            findings.append(ForensicFinding(
                finding_type      = FindingType.DUPLICATE_SEQUENCE,
                severity          = FINDING_SEVERITY[FindingType.DUPLICATE_SEQUENCE],
                affected_sequence = seq,
                message           = msg,
            ))
            tamper_evidence.append(msg)
        seen.add(seq)

        if seq != expected:
            if seq > expected:
                missing = list(range(expected, seq))
                msg = (
                    f"Sequence gap: events {missing} are missing — "
                    f"possible deletion between events {expected - 1} and {seq}."
                )
                findings.append(ForensicFinding(
                    finding_type      = FindingType.SEQUENCE_GAP,
                    severity          = FINDING_SEVERITY[FindingType.SEQUENCE_GAP],
                    affected_sequence = seq,
                    message           = msg,
                ))
                tamper_evidence.append(msg)
            else:
                msg = (
                    f"Sequence number went backwards ({expected} -> {seq}) — "
                    f"possible reordering."
                )
                findings.append(ForensicFinding(
                    finding_type      = FindingType.SEQUENCE_GAP,
                    severity          = FINDING_SEVERITY[FindingType.SEQUENCE_GAP],
                    affected_sequence = seq,
                    message           = msg,
                ))
                tamper_evidence.append(msg)
            expected = seq + 1
        else:
            expected += 1


def _check_workflow(
    sorted_events:     list[dict[str, Any]],
    findings:          list[ForensicFinding],
    tamper_evidence:   list[str],
    workflow_anomalies: list[str],
) -> None:
    """
    Validate the expected AFEM event workflow.

    Rules checked:
    - session_start must be the very first event (sequence 0).
    - session_end must be the very last event.
    - No more than one session_start or session_end per session.
    - Every tool_call must be immediately followed by a tool_result.

    Violations populate both findings and workflow_anomalies so that
    Phase 4 (Attribution) can consume them as attribution signals.
    """
    if not sorted_events:
        return

    event_types = [e.get("event_type", "") for e in sorted_events]

    # Rule 1: session_start must be first.
    if event_types[0] != _SESSION_START:
        msg = (
            f"Expected session_start as first event (seq 0); "
            f"got '{event_types[0]}'. "
            f"Session may have been truncated at the start."
        )
        _add_workflow(msg, sorted_events[0].get("sequence_number", 0),
                      findings, tamper_evidence, workflow_anomalies)

    # Rule 2: session_end must be last.
    if event_types[-1] != _SESSION_END:
        msg = (
            f"Expected session_end as last event; "
            f"got '{event_types[-1]}' at sequence "
            f"{sorted_events[-1].get('sequence_number', '?')}. "
            f"Session may have been interrupted."
        )
        _add_workflow(msg, sorted_events[-1].get("sequence_number", None),
                      findings, tamper_evidence, workflow_anomalies)

    # Rule 3: exactly one session_start.
    start_count = event_types.count(_SESSION_START)
    if start_count > 1:
        msg = (
            f"Found {start_count} session_start events — expected exactly 1. "
            f"Possible session concatenation or insertion."
        )
        _add_workflow(msg, None, findings, tamper_evidence, workflow_anomalies)

    # Rule 4: exactly one session_end.
    end_count = event_types.count(_SESSION_END)
    if end_count > 1:
        msg = (
            f"Found {end_count} session_end events — expected exactly 1. "
            f"Possible session concatenation or insertion."
        )
        _add_workflow(msg, None, findings, tamper_evidence, workflow_anomalies)

    # Rule 5: every tool_call followed by tool_result.
    for i, etype in enumerate(event_types):
        if etype == _TOOL_CALL:
            next_type = event_types[i + 1] if i + 1 < len(event_types) else None
            if next_type != _TOOL_RESULT:
                seq = sorted_events[i].get("sequence_number", i)
                msg = (
                    f"tool_call at sequence {seq} is not immediately followed by "
                    f"tool_result (got '{next_type}'). "
                    f"Possible event deletion or insertion between tool pair."
                )
                _add_workflow(msg, seq, findings, tamper_evidence, workflow_anomalies)


def _add_workflow(
    msg:               str,
    affected_seq:      int | None,
    findings:          list[ForensicFinding],
    tamper_evidence:   list[str],
    workflow_anomalies: list[str],
) -> None:
    """Add a WORKFLOW_ANOMALY finding and update both tamper_evidence and workflow_anomalies."""
    findings.append(ForensicFinding(
        finding_type      = FindingType.WORKFLOW_ANOMALY,
        severity          = FINDING_SEVERITY[FindingType.WORKFLOW_ANOMALY],
        affected_sequence = affected_seq,
        message           = msg,
    ))
    tamper_evidence.append(msg)
    workflow_anomalies.append(msg)


def _check_timestamps(
    sorted_events:   list[dict[str, Any]],
    findings:        list[ForensicFinding],
    tamper_evidence: list[str],
) -> None:
    """
    Verify that ISO-8601 timestamps are non-decreasing.

    A timestamp reversal is not definitive evidence of tampering (clocks can
    skew) but it is a forensically notable anomaly that warrants investigation.
    Only parseable timestamps are compared; unparseable values are skipped.
    """
    prev_ts:  datetime | None = None
    prev_seq: int | None      = None

    for event in sorted_events:
        ts_str = event.get("timestamp", "")
        seq    = event.get("sequence_number")
        if not ts_str:
            continue
        try:
            # Accept both Z-suffix and +00:00 UTC notation.
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            continue

        if prev_ts is not None and ts < prev_ts:
            msg = (
                f"Timestamp anomaly: event {seq} has timestamp {ts_str!r} "
                f"which is earlier than event {prev_seq} timestamp. "
                f"Possible event reordering or clock manipulation."
            )
            findings.append(ForensicFinding(
                finding_type      = FindingType.TIMESTAMP_ANOMALY,
                severity          = FINDING_SEVERITY[FindingType.TIMESTAMP_ANOMALY],
                affected_sequence = seq,
                message           = msg,
            ))
            tamper_evidence.append(msg)

        prev_ts  = ts
        prev_seq = seq


def _check_session_end(
    sorted_events:   list[dict[str, Any]],
    findings:        list[ForensicFinding],
    tamper_evidence: list[str],
) -> bool:
    """
    Check SessionEndEvent presence and total_events cross-check.

    Returns True if the session is structurally complete (SessionEndEvent
    present and total_events matches actual preceding event count).
    """
    end_events = [e for e in sorted_events if e.get("event_type") == _SESSION_END]

    if not end_events:
        msg = (
            "No session_end event found. "
            "Session was not completed normally — "
            "may have been interrupted or truncated after writing."
        )
        findings.append(ForensicFinding(
            finding_type      = FindingType.MISSING_END_EVENT,
            severity          = FINDING_SEVERITY[FindingType.MISSING_END_EVENT],
            affected_sequence = None,
            message           = msg,
        ))
        tamper_evidence.append(msg)
        return False

    # Use the last session_end event found.
    end_event    = end_events[-1]
    end_seq      = end_event.get("sequence_number")
    total_claimed = end_event.get("total_events")

    if total_claimed is None:
        msg = (
            f"session_end at sequence {end_seq} is missing total_events field."
        )
        findings.append(ForensicFinding(
            finding_type      = FindingType.MISSING_FIELD,
            severity          = FINDING_SEVERITY[FindingType.MISSING_FIELD],
            affected_sequence = end_seq,
            message           = msg,
        ))
        tamper_evidence.append(msg)
        return False

    # Count events that appear before the session_end in sequence order.
    events_before_end = sum(
        1 for e in sorted_events
        if e.get("sequence_number", -1) < (end_seq if end_seq is not None else float("inf"))
    )

    if events_before_end != total_claimed:
        # Distinguish truncation (fewer events than claimed) from
        # insertion (more events than claimed).
        if events_before_end < total_claimed:
            finding_type = FindingType.TRUNCATED_SESSION
            direction    = (
                f"only {events_before_end} events found before session_end "
                f"but total_events declares {total_claimed}. "
                f"Session file may be truncated."
            )
        else:
            finding_type = FindingType.TOTAL_EVENTS_MISMATCH
            direction    = (
                f"{events_before_end} events found before session_end "
                f"but total_events declares {total_claimed}. "
                f"Possible insertion of events."
            )

        msg = (
            f"session_end total_events mismatch at sequence {end_seq}: "
            + direction
        )
        findings.append(ForensicFinding(
            finding_type      = finding_type,
            severity          = FINDING_SEVERITY[finding_type],
            affected_sequence = end_seq,
            message           = msg,
        ))
        tamper_evidence.append(msg)
        return False

    return True


# ---------------------------------------------------------------------------
# Hash-chain verification for a single event
# ---------------------------------------------------------------------------


def _verify_one(event: dict[str, Any], expected_prev: str) -> VerificationResult:
    """
    Verify a single event's chain linkage and content hash.

    If either hash field is absent (already caught by _check_mandatory_fields),
    this function records a MISSING_FIELD failure rather than conflating it
    with a CHAIN_LINK_MISMATCH.
    """
    seq        = event.get("sequence_number", -1)
    event_type = event.get("event_type", "unknown")
    actual_prev = event.get("previous_hash", "")
    actual_hash = event.get("event_hash", "")

    # Detect missing hash fields explicitly (not via hash mismatch).
    if "previous_hash" not in event or "event_hash" not in event:
        missing = [f for f in ("previous_hash", "event_hash") if f not in event]
        reason = (
            f"Event {seq} ({event_type}): missing fields {missing}. "
            f"Cannot verify hash chain for this event."
        )
        return VerificationResult(
            sequence_number = seq,
            event_type      = event_type,
            is_valid        = False,
            expected_prev   = expected_prev,
            actual_prev     = actual_prev,
            expected_hash   = "",
            actual_hash     = actual_hash,
            failure_reason  = reason,
            finding_type    = FindingType.MISSING_FIELD,
            severity        = FINDING_SEVERITY[FindingType.MISSING_FIELD],
        )

    # Recompute using the stored previous_hash so we independently verify
    # the stored hash rather than re-deriving it from expected_prev.
    work          = {k: v for k, v in event.items() if k != "event_hash"}
    expected_hash = compute_event_hash(work)

    linkage_ok = actual_prev == expected_prev
    content_ok = actual_hash == expected_hash
    is_valid   = linkage_ok and content_ok

    failure_reason:  str | None         = None
    finding_type:    FindingType | None = None
    severity:        Severity | None    = None

    if not is_valid:
        reasons = []
        # CONTENT_HASH_MISMATCH takes precedence as the more specific finding.
        if not content_ok:
            finding_type = FindingType.CONTENT_HASH_MISMATCH
            severity     = FINDING_SEVERITY[FindingType.CONTENT_HASH_MISMATCH]
            reasons.append(
                f"Event {seq} ({event_type}): event_hash mismatch — "
                f"stored {actual_hash[:12]}... recomputed {expected_hash[:12]}... "
                f"(event payload was modified after sealing)"
            )
        if not linkage_ok:
            if finding_type is None:
                finding_type = FindingType.CHAIN_LINK_MISMATCH
                severity     = FINDING_SEVERITY[FindingType.CHAIN_LINK_MISMATCH]
            reasons.append(
                f"Event {seq} ({event_type}): previous_hash mismatch — "
                f"expected {expected_prev[:12]}... "
                f"got {actual_prev[:12]}... "
                f"(deletion or reordering before this event)"
            )
        failure_reason = "; ".join(reasons)

    return VerificationResult(
        sequence_number = seq,
        event_type      = event_type,
        is_valid        = is_valid,
        expected_prev   = expected_prev,
        actual_prev     = actual_prev,
        expected_hash   = expected_hash,
        actual_hash     = actual_hash,
        failure_reason  = failure_reason,
        finding_type    = finding_type,
        severity        = severity,
    )


# ---------------------------------------------------------------------------
# EvidenceTrust derivation
# ---------------------------------------------------------------------------


def _derive_trust(
    chain_valid:      bool,
    session_complete: bool,
    findings:         list[ForensicFinding],
) -> EvidenceTrust:
    """
    Derive the session-level EvidenceTrust verdict.

    Rules (evaluated in priority order):
    1. Any CRITICAL finding → COMPROMISED
    2. chain_valid=False → COMPROMISED
    3. Any HIGH finding → DEGRADED
    4. session_complete=False → DEGRADED
    5. Any MEDIUM finding → DEGRADED
    6. No findings, chain_valid=True, session_complete=True → TRUSTED
    """
    if not chain_valid:
        return EvidenceTrust.COMPROMISED

    for finding in findings:
        if finding.severity == Severity.CRITICAL:
            return EvidenceTrust.COMPROMISED

    for finding in findings:
        if finding.severity in (Severity.HIGH, Severity.MEDIUM):
            return EvidenceTrust.DEGRADED

    if not session_complete:
        return EvidenceTrust.DEGRADED

    return EvidenceTrust.TRUSTED


# ---------------------------------------------------------------------------
# Unrecoverable report (all lines corrupted)
# ---------------------------------------------------------------------------


def _build_unrecoverable_report(
    session_path: Path,
    corrupt_findings: list[ForensicFinding],
) -> IntegrityReport:
    """Build a minimal UNKNOWN-trust report when no events could be parsed."""
    session_id = session_path.stem
    msg        = f"All JSONL lines in {session_path.name} are corrupted — cannot verify."
    return IntegrityReport(
        session_id         = session_id,
        total_events       = 0,
        chain_valid        = False,
        first_broken_seq   = None,
        events             = [],
        tamper_evidence    = [f.message for f in corrupt_findings] + [msg],
        genesis_hash       = "",
        terminal_hash      = "",
        verified_at        = datetime.now(timezone.utc).isoformat(),
        evidence_trust     = EvidenceTrust.UNKNOWN,
        session_complete   = False,
        first_failure_type = FindingType.CORRUPTED_JSON,
        workflow_anomalies = [],
        findings           = list(corrupt_findings),
    )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _log_report(report: IntegrityReport, path: Path) -> None:
    """Log a one-line summary of the verification result."""
    if report.chain_valid:
        logger.info(
            "Integrity VERIFIED.  session=%s  trust=%s  events=%d  terminal=%s",
            report.session_id,
            report.evidence_trust,
            report.total_events,
            report.terminal_hash[:12] if report.terminal_hash else "N/A",
        )
    else:
        logger.warning(
            "Integrity FAILED.  session=%s  trust=%s  first_broken=%s  "
            "findings=%d  path=%s",
            report.session_id,
            report.evidence_trust,
            report.first_broken_seq,
            len(report.findings),
            path,
        )