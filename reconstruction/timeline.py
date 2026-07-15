"""
AFEM Phase 3 — Timeline Reconstruction
=======================================
Deterministic forensic timeline reconstructor.

Consumes
--------
- session JSONL file (``data/evidence/sessions/<uuid>.jsonl``)
- ``IntegrityReport`` from Phase 2

Produces
--------
- ``TimelineReport`` — structured, ordered, annotated forensic timeline

Design principles
-----------------
1.  Deterministic ordering by ``sequence_number``, not by timestamp.
    Timestamps are recorded as supporting temporal evidence but are never
    used as the primary ordering signal because they may be missing,
    duplicated, or non-monotonic (detected by the verifier in Phase 2).

    
2.  Pair-aware reconstruction.
    ``tool_call`` + ``tool_result`` events are collapsed into a single
    ``TimelineEntry`` with ``event_type="tool_action"``. This mirrors how a
    human investigator reads the timeline: "the agent called search_email
    and received N results." Orphaned tool_calls (no following tool_result)
    are reconstructed as individual entries and flagged with an anomaly.

3.  Integrity annotation.
    Every ``TimelineEntry`` carries an ``integrity_status`` field propagated
    from the corresponding ``VerificationResult.is_valid`` flags in the
    IntegrityReport. Compromised entries are annotated, not silently excluded.
    Phase 4 and 5 use these annotations to qualify attribution confidence and
    report limitations.

4.  Completeness derivation.
    ``ReconstructionCompleteness`` is derived from:
    - EvidenceTrust from IntegrityReport
    - session_complete flag from IntegrityReport
    - Presence of sequence gaps
    - Presence of orphaned tool_calls

5.  No LLM involvement.
    The reconstructor is pure Python. It is deterministic, testable, and
    reproducible — a hard requirement for a forensic tool.

Public API
----------
    reconstruct_timeline(session_path, integrity_report) -> TimelineReport
    reconstruct_from_session_id(session_id, sessions_dir, integrity_report) -> TimelineReport

Usage
-----
    from reconstruction.timeline import reconstruct_timeline
    from integrity.verifier import verify_session

    report = verify_session(path)
    timeline = reconstruct_timeline(path, report)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from schemas.integrity import EvidenceTrust, IntegrityReport, VerificationResult
from schemas.report import (
    ReconstructionCompleteness,
    TimelineEntry,
    TimelineReport,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event type constants (must match EvidenceCollector / schemas/evidence.py)
# ---------------------------------------------------------------------------

_SESSION_START   = "session_start"
_USER_PROMPT     = "user_prompt"
_TOOL_CALL       = "tool_call"
_TOOL_RESULT     = "tool_result"
_AGENT_RESPONSE  = "agent_response"
_SESSION_END     = "session_end"

# Actor mapping — which AFEM event type is initiated by which actor
_ACTOR_MAP: dict[str, str] = {
    _SESSION_START:  "system",
    _USER_PROMPT:    "user",
    _TOOL_CALL:      "agent",
    _TOOL_RESULT:    "agent",
    _AGENT_RESPONSE: "agent",
    _SESSION_END:    "system",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def reconstruct_timeline(
    session_path:     Path,
    integrity_report: IntegrityReport,
) -> TimelineReport:
    """
    Reconstruct a forensic timeline from a session JSONL and IntegrityReport.

    Parameters
    ----------
    session_path :
        Path to the sealed (or unsealed) session JSONL file.
    integrity_report :
        The ``IntegrityReport`` produced by ``integrity.verifier.verify_session()``
        for this session. Must not be None — the integrity report is a required
        input, not an optional enhancement.

    Returns
    -------
    TimelineReport
        Fully populated timeline report ready for Phase 4 consumption.
    """
    session_id = integrity_report.session_id
    logger.info("Reconstructing timeline.  session=%s  path=%s", session_id, session_path)

    # --- Load JSONL events (raw dicts) ---
    events = _load_events(session_path)

    if not events:
        logger.warning("No events loaded — returning minimal FAILED timeline.")
        return _empty_report(session_id, integrity_report)

    # --- Sort by sequence_number (primary ordering signal) ---
    events.sort(key=lambda e: e.get("sequence_number", 0))

    # --- Build per-sequence integrity lookup from IntegrityReport ---
    integrity_by_seq: dict[int, VerificationResult] = {
        r.sequence_number: r for r in integrity_report.events
    }

    # --- Extract user prompt for report metadata ---
    user_prompt = _extract_user_prompt(events)

    # --- Pair tool_call / tool_result events ---
    entries:   list[TimelineEntry] = []
    anomalies: list[str]           = []
    tool_sequence: list[str]       = []

    i = 0
    while i < len(events):
        event     = events[i]
        etype     = event.get("event_type", "")
        seq       = event.get("sequence_number", i)
        int_check = integrity_by_seq.get(seq)

        if etype == _TOOL_CALL:
            # Look ahead for the immediately following tool_result
            next_event = events[i + 1] if i + 1 < len(events) else None
            next_etype = (next_event or {}).get("event_type", "")

            if next_etype == _TOOL_RESULT:
                entry = _build_tool_action_entry(
                    event, next_event, integrity_by_seq
                )
                tool_name = entry.tool_name
                if tool_name:
                    tool_sequence.append(tool_name)
                entries.append(entry)
                i += 2  # consume both events
            else:
                # Orphaned tool_call
                entry = _build_single_entry(event, int_check)
                entry.anomaly = "orphaned_tool_call: no following tool_result detected"
                anomalies.append(
                    f"Orphaned tool_call at sequence {seq} "
                    f"(tool={event.get('tool_name','?')}) — "
                    f"no following tool_result."
                )
                tool_name = event.get("tool_name")
                if tool_name:
                    tool_sequence.append(tool_name)
                entries.append(entry)
                i += 1

        elif etype == _TOOL_RESULT:
            # Unmatched tool_result (the tool_call was already consumed or missing)
            entry = _build_single_entry(event, int_check)
            entry.anomaly = "orphaned_tool_result: no preceding tool_call in sequence"
            anomalies.append(
                f"Orphaned tool_result at sequence {seq} — "
                f"no preceding tool_call."
            )
            entries.append(entry)
            i += 1

        else:
            entry = _build_single_entry(event, int_check)
            entries.append(entry)
            i += 1

    # --- Session-level anomaly detection ---
    _detect_session_anomalies(events, entries, anomalies, integrity_report)

    # --- Derive completeness ---
    completeness = _derive_completeness(integrity_report, anomalies, events)

    # --- Build report ---
    evidence_trust = (
        integrity_report.evidence_trust.value
        if hasattr(integrity_report.evidence_trust, "value")
        else str(integrity_report.evidence_trust)
    )

    report = TimelineReport(
        session_id              = session_id,
        user_prompt             = user_prompt,
        entries                 = entries,
        completeness            = completeness,
        anomalies               = anomalies,
        tool_sequence           = tool_sequence,
        integrity_report        = integrity_report,
        evidence_trust          = evidence_trust,
        total_events_in_session = len(events),
        total_timeline_entries  = len(entries),
    )

    logger.info(
        "Timeline reconstructed.  session=%s  entries=%d  completeness=%s  trust=%s",
        session_id, len(entries), completeness.value, evidence_trust,
    )
    return report


def reconstruct_from_session_id(
    session_id:       str,
    sessions_dir:     Path,
    integrity_report: IntegrityReport,
) -> TimelineReport:
    """
    Convenience wrapper: locate the session file by UUID and reconstruct.

    Parameters
    ----------
    session_id :
        The UUID string of the session to reconstruct.
    sessions_dir :
        Directory containing per-session .jsonl files.
    integrity_report :
        The IntegrityReport for this session.

    Returns
    -------
    TimelineReport

    Raises
    ------
    FileNotFoundError
        If no .jsonl file matching session_id exists in sessions_dir.
    """
    session_path = sessions_dir / f"{session_id}.jsonl"
    if not session_path.exists():
        raise FileNotFoundError(
            f"Session file not found: {session_path}"
        )
    return reconstruct_timeline(session_path, integrity_report)


# ---------------------------------------------------------------------------
# Entry builders
# ---------------------------------------------------------------------------


def _build_single_entry(
    event:      dict[str, Any],
    int_result: Optional[VerificationResult],
) -> TimelineEntry:
    """Build a TimelineEntry from a single JSONL event."""
    etype  = event.get("event_type", "unknown")
    seq    = event.get("sequence_number", 0)
    actor  = _ACTOR_MAP.get(etype, "unknown")
    ts     = event.get("timestamp")

    action, input_summary, output_summary = _describe_event(event)

    integrity_status = _resolve_integrity(int_result)

    return TimelineEntry(
        sequence_number      = seq,
        timestamp            = ts,
        event_type           = etype,
        actor                = actor,
        action               = action,
        input_summary        = input_summary,
        output_summary       = output_summary,
        integrity_status     = integrity_status,
        raw_sequence_numbers = [seq],
    )


def _build_tool_action_entry(
    call_event:       dict[str, Any],
    result_event:     dict[str, Any],
    integrity_by_seq: dict[int, VerificationResult],
) -> TimelineEntry:
    """
    Build a single TimelineEntry from a matched tool_call + tool_result pair.

    The entry uses the tool_call's sequence_number as the primary key.
    Both sequence numbers are recorded in raw_sequence_numbers so Phase 5
    can cross-reference back to the raw JSONL.

    Integrity status: if either event is invalid, the entry is marked invalid.
    """
    call_seq   = call_event.get("sequence_number", 0)
    result_seq = result_event.get("sequence_number", call_seq + 1)
    tool_name  = call_event.get("tool_name") or call_event.get("input_data", {}).get("tool_name")

    call_int   = integrity_by_seq.get(call_seq)
    result_int = integrity_by_seq.get(result_seq)

    # Either event invalid → entry invalid
    if call_int and result_int:
        integrity_status = "valid" if (call_int.is_valid and result_int.is_valid) else "invalid"
    elif call_int:
        integrity_status = "valid" if call_int.is_valid else "invalid"
    elif result_int:
        integrity_status = "valid" if result_int.is_valid else "invalid"
    else:
        integrity_status = "unknown"

    # Build input summary from tool_call
    input_data    = call_event.get("input_data", {})
    input_summary = _summarise_dict(input_data, max_len=120)

    # Build output summary and artifact refs from tool_result
    output_data   = result_event.get("output_data", {})
    row_count     = result_event.get("row_count")
    artifact_refs = result_event.get("evidence_refs", [])

    # Extract artifact references from output_data.
    #
    # search_email stores multiple references under ``evidence_refs``.
    # retrieve_email stores one execution-time artifact reference directly
    # as ``output_data``. Wrapping that dictionary in a list preserves its
    # bounded forensic snapshot for downstream attribution.
    if not artifact_refs and isinstance(output_data, dict):
        nested_refs = output_data.get("evidence_refs")

        if isinstance(nested_refs, list):
            artifact_refs = nested_refs
        elif (
            output_data.get("artifact_type")
            and output_data.get("artifact_id") is not None
        ):
            artifact_refs = [output_data]

    output_summary = _summarise_tool_result(tool_name, output_data, row_count)

    action = f"Invoked {tool_name or 'unknown_tool'}"
    if row_count is not None:
        action += f" → {row_count} result(s) returned"

    anomaly = ""
    if integrity_status == "invalid":
        anomaly = "integrity_failure: one or both events in this tool pair failed hash verification"

    return TimelineEntry(
        sequence_number      = call_seq,
        timestamp            = call_event.get("timestamp"),
        event_type           = "tool_action",
        actor                = "agent",
        action               = action,
        tool_name            = tool_name,
        artifact_refs        = artifact_refs,
        input_summary        = input_summary,
        output_summary       = output_summary,
        integrity_status     = integrity_status,
        anomaly              = anomaly,
        raw_sequence_numbers = [call_seq, result_seq],
    )


# ---------------------------------------------------------------------------
# Describe a single event in human-readable terms
# ---------------------------------------------------------------------------


def _describe_event(event: dict[str, Any]) -> tuple[str, Optional[str], Optional[str]]:
    """
    Return (action, input_summary, output_summary) for a single event.

    These strings are used in Phase 5 report rendering. They are short and
    human-readable, not verbatim event content.
    """
    etype = event.get("event_type", "unknown")

    if etype == _SESSION_START:
        model  = event.get("model", "unknown")
        prompt = _truncate(event.get("user_prompt", ""), 80)
        return (
            f"Agent session initiated (model: {model})",
            f"Prompt: {prompt}" if prompt else None,
            None,
        )

    if etype == _USER_PROMPT:
        content = _truncate(event.get("content", ""), 120)
        return (
            "User prompt submitted to agent",
            content or None,
            None,
        )

    if etype == _TOOL_CALL:
        tool     = event.get("tool_name", "unknown")
        inp      = event.get("input_data", {})
        inp_str  = _summarise_dict(inp, max_len=100)
        return (
            f"Agent invoked {tool}",
            inp_str or None,
            None,
        )

    if etype == _TOOL_RESULT:
        tool       = event.get("tool_name", "unknown")
        row_count  = event.get("row_count")
        error      = event.get("error")
        if error:
            return (f"{tool} returned error", None, f"Error: {_truncate(str(error), 80)}")
        out = f"{row_count} result(s)" if row_count is not None else "result received"
        return (f"{tool} returned", None, out)

    if etype == _AGENT_RESPONSE:
        content = _truncate(event.get("content", ""), 120)
        return (
            "Agent generated final response",
            None,
            content or None,
        )

    if etype == _SESSION_END:
        status = event.get("status", "unknown")
        total  = event.get("total_events", "?")
        return (
            f"Session terminated (status: {status},preceding events: {total})",
            None,
            None,
        )

    # Unknown event type
    return (f"Unknown event: {etype}", None, None)


# ---------------------------------------------------------------------------
# Session-level anomaly detection (runs after entries are built)
# ---------------------------------------------------------------------------


def _detect_session_anomalies(
    events:           list[dict[str, Any]],
    entries:          list[TimelineEntry],
    anomalies:        list[str],
    integrity_report: IntegrityReport,
) -> None:
    """
    Add session-level anomalies that could not be detected per-entry.

    - Sequence gaps (from IntegrityReport findings or raw sequence inspection)
    - Integrity failures on non-tool entries
    - Missing session_start or session_end
    """
    event_types = [e.get("event_type", "") for e in events]

    if _SESSION_START not in event_types:
        anomalies.append(
            "session_start event is missing from the JSONL file."
        )

    if _SESSION_END not in event_types:
        anomalies.append(
            "session_end event is missing — session was not completed normally."
        )

    # Propagate integrity-report workflow anomalies
    for wa in integrity_report.workflow_anomalies:
        if wa not in anomalies:
            anomalies.append(wa)

    # Flag any compromised entries in the anomaly list
    compromised = [e for e in entries if e.integrity_status == "invalid"]
    if compromised:
        seqs = [str(e.sequence_number) for e in compromised]
        anomalies.append(
            f"Integrity failure on timeline entries at sequence(s): "
            f"{', '.join(seqs)}."
        )


# ---------------------------------------------------------------------------
# Completeness derivation
# ---------------------------------------------------------------------------


def _derive_completeness(
    integrity_report: IntegrityReport,
    anomalies:        list[str],
    events:           list[dict[str, Any]],
) -> ReconstructionCompleteness:
    """
    Derive ReconstructionCompleteness from the integrity report and anomalies.

    COMPLETE    TRUSTED trust, session_complete=True, no anomalies
    PARTIAL     DEGRADED trust, OR session_complete=False, OR anomalies exist
    MINIMAL     COMPROMISED trust AND anomalies AND few events
    FAILED      No events or UNKNOWN trust with no reconstructible content
    """
    trust = (
        integrity_report.evidence_trust.value
        if hasattr(integrity_report.evidence_trust, "value")
        else str(integrity_report.evidence_trust)
    )

    if not events:
        return ReconstructionCompleteness.FAILED

    if trust == "unknown":
        return ReconstructionCompleteness.FAILED

    if trust == "compromised":
        if len(events) > 2 and anomalies:
            return ReconstructionCompleteness.MINIMAL
        return ReconstructionCompleteness.FAILED

    # TRUSTED or DEGRADED
    has_anomalies     = bool(anomalies)
    session_complete  = integrity_report.session_complete

    if trust == "trusted" and session_complete and not has_anomalies:
        return ReconstructionCompleteness.COMPLETE

    if trust == "degraded" or not session_complete or has_anomalies:
        return ReconstructionCompleteness.PARTIAL

    return ReconstructionCompleteness.COMPLETE


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _load_events(path: Path) -> list[dict[str, Any]]:
    """
    Load JSONL events from file. Silently skips blank and malformed lines.

    The verifier already reports corrupt JSON as a finding. The reconstructor
    does not re-raise those errors — it reconstructs what it can.
    """
    events: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line during reconstruction.")
    return events


def _extract_user_prompt(events: list[dict[str, Any]]) -> Optional[str]:
    """Extract the user prompt from session_start or user_prompt events."""
    for event in events:
        etype = event.get("event_type", "")
        if etype == _SESSION_START:
            return event.get("user_prompt")
        if etype == _USER_PROMPT:
            return event.get("content")
    return None


def _resolve_integrity(result: Optional[VerificationResult]) -> str:
    """Return 'valid', 'invalid', or 'unknown' from a VerificationResult."""
    if result is None:
        return "unknown"
    return "valid" if result.is_valid else "invalid"


def _summarise_dict(d: Any, max_len: int = 100) -> str:
    """Produce a short string representation of a dict for display."""
    if not d:
        return ""
    if isinstance(d, dict):
        parts = [f"{k}={repr(v)}" for k, v in list(d.items())[:3]]
        summary = ", ".join(parts)
    else:
        summary = str(d)
    return _truncate(summary, max_len)


def _summarise_tool_result(
    tool_name:  Optional[str],
    output_data: Any,
    row_count:   Optional[int],
) -> str:
    """Produce a short result summary for a tool_result event."""
    parts = []
    if row_count is not None:
        parts.append(f"{row_count} record(s) returned")
    if isinstance(output_data, dict):
        if "error" in output_data:
            parts.append(f"error: {_truncate(str(output_data['error']), 60)}")
        elif "evidence_refs" in output_data:
            refs = output_data["evidence_refs"]
            parts.append(f"artifact refs: {len(refs)}")
    if not parts:
        parts.append("result received")
    return "; ".join(parts)


def _truncate(text: str, max_len: int) -> str:
    """Truncate a string to max_len characters, appending '...' if needed."""
    if not text:
        return ""
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _empty_report(session_id: str, integrity_report: IntegrityReport) -> TimelineReport:
    """Return a minimal FAILED TimelineReport when no events can be loaded."""
    evidence_trust = (
        integrity_report.evidence_trust.value
        if hasattr(integrity_report.evidence_trust, "value")
        else str(integrity_report.evidence_trust)
    )
    return TimelineReport(
        session_id              = session_id,
        completeness            = ReconstructionCompleteness.FAILED,
        anomalies               = ["No events could be loaded from the session file."],
        integrity_report        = integrity_report,
        evidence_trust          = evidence_trust,
        total_events_in_session = 0,
        total_timeline_entries  = 0,
    )
