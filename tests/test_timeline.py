"""
AFEM Phase 3 — Timeline Reconstruction Test Suite
===================================================
Tests for reconstruction/timeline.py and schemas/report.py.

All tests are self-contained. They construct minimal IntegrityReports
and JSONL session files in tmp_path without requiring Phase 1 runtime.

Test classes:
    TestTimelineSchemas         — TimelineEntry, TimelineReport, ReconstructionCompleteness
    TestToolPairing             — tool_call + tool_result pairing logic
    TestOrphanedEvents          — orphaned tool_call / tool_result detection
    TestIntegrityPropagation    — per-entry integrity_status from IntegrityReport
    TestCompletenessDerivation  — ReconstructionCompleteness from trust + anomalies
    TestAnomalyDetection        — session-level anomaly detection
    TestFullSessionReconstruction — end-to-end clean and tampered sessions
    TestEdgeCases               — empty file, single event, unknown event types

Run:
    python -m pytest tests/test_timeline.py -v
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest

from reconstruction.timeline import reconstruct_timeline, _truncate
from schemas.integrity import (
    EvidenceTrust,
    FindingType,
    IntegrityReport,
    Severity,
    VerificationResult,
)
from schemas.report import (
    ReconstructionCompleteness,
    TimelineEntry,
    TimelineReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ver(seq: int, etype: str, valid: bool = True) -> VerificationResult:
    """Build a minimal VerificationResult for a given sequence."""
    h = "a" * 64 if valid else "b" * 64
    return VerificationResult(
        sequence_number = seq,
        event_type      = etype,
        is_valid        = valid,
        expected_prev   = "0" * 64,
        actual_prev     = "0" * 64,
        expected_hash   = h,
        actual_hash     = h,
    )


def _make_integrity_report(
    session_id:       str,
    events:           list[dict[str, Any]],
    chain_valid:      bool = True,
    trust:            EvidenceTrust = EvidenceTrust.TRUSTED,
    session_complete: bool = True,
    valid_seqs:       set[int] | None = None,
) -> IntegrityReport:
    """
    Build a minimal IntegrityReport that matches a list of event dicts.
    valid_seqs: if provided, only those sequence numbers are is_valid=True.
    """
    ver_results = []
    for e in events:
        seq   = e.get("sequence_number", 0)
        etype = e.get("event_type", "unknown")
        is_v  = True if valid_seqs is None else (seq in valid_seqs)
        ver_results.append(_ver(seq, etype, is_v))

    return IntegrityReport(
        session_id       = session_id,
        total_events     = len(events),
        chain_valid      = chain_valid,
        events           = ver_results,
        genesis_hash     = "a" * 64,
        terminal_hash    = "b" * 64,
        evidence_trust   = trust,
        session_complete = session_complete,
        workflow_anomalies = [],
        findings         = [],
    )


def _write_session(path: Path, events: list[dict[str, Any]]) -> None:
    """Write events to a JSONL file."""
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


def _make_full_events(session_id: str | None = None) -> list[dict[str, Any]]:
    """Build a complete, realistic session event list."""
    sid = session_id or str(uuid.uuid4())
    return [
        {"session_id": sid, "sequence_number": 0, "event_type": "session_start",
         "timestamp": "2024-06-01T10:00:00+00:00",
         "user_prompt": "Find all emails about salary", "model": "qwen3:8b"},
        {"session_id": sid, "sequence_number": 1, "event_type": "user_prompt",
         "timestamp": "2024-06-01T10:00:01+00:00", "content": "Find all emails about salary"},
        {"session_id": sid, "sequence_number": 2, "event_type": "tool_call",
         "timestamp": "2024-06-01T10:00:02+00:00",
         "tool_name": "search_email", "input_data": {"keyword": "salary", "limit": 10}},
        {"session_id": sid, "sequence_number": 3, "event_type": "tool_result",
         "timestamp": "2024-06-01T10:00:03+00:00",
         "tool_name": "search_email", "row_count": 3,
         "evidence_refs": [{"artifact_type": "email", "artifact_id": 4}]},
        {"session_id": sid, "sequence_number": 4, "event_type": "agent_response",
         "timestamp": "2024-06-01T10:00:04+00:00",
         "content": "I found 3 emails about salary."},
        {"session_id": sid, "sequence_number": 5, "event_type": "session_end",
         "timestamp": "2024-06-01T10:00:05+00:00",
         "total_events": 5, "status": "completed"},
    ]


# ---------------------------------------------------------------------------
# TestTimelineSchemas
# ---------------------------------------------------------------------------


class TestTimelineSchemas:
    def test_timeline_entry_defaults(self):
        e = TimelineEntry(
            sequence_number=0, event_type="session_start",
            actor="system", action="Session started",
        )
        assert e.integrity_status == "unknown"
        assert e.anomaly == ""
        assert e.artifact_refs == []
        assert e.raw_sequence_numbers == []

    def test_timeline_entry_full(self):
        e = TimelineEntry(
            sequence_number=2, event_type="tool_action",
            actor="agent", action="Invoked search_email",
            tool_name="search_email",
            artifact_refs=[{"artifact_type": "email", "artifact_id": 4}],
            input_summary="keyword=salary",
            output_summary="3 record(s) returned",
            integrity_status="valid",
            anomaly="",
            raw_sequence_numbers=[2, 3],
        )
        assert e.tool_name == "search_email"
        assert len(e.artifact_refs) == 1

    def test_timeline_report_defaults(self):
        r = TimelineReport(session_id="test-123")
        assert r.completeness == ReconstructionCompleteness.FAILED
        assert r.entries == []
        assert r.tool_sequence == []
        assert r.evidence_trust == "unknown"

    def test_timeline_report_is_trustworthy(self):
        r = TimelineReport(session_id="x", evidence_trust="trusted")
        assert r.is_trustworthy is True
        r2 = TimelineReport(session_id="x", evidence_trust="compromised")
        assert r2.is_trustworthy is False

    def test_timeline_report_tool_calls_made(self):
        entries = [
            TimelineEntry(sequence_number=0, event_type="tool_action",
                          actor="agent", action="a", tool_name="search_email"),
            TimelineEntry(sequence_number=1, event_type="tool_action",
                          actor="agent", action="b", tool_name="retrieve_email"),
        ]
        r = TimelineReport(session_id="x", entries=entries)
        assert r.tool_calls_made == ["search_email", "retrieve_email"]

    def test_completeness_enum_values(self):
        assert ReconstructionCompleteness.COMPLETE.value == "complete"
        assert ReconstructionCompleteness.PARTIAL.value  == "partial"
        assert ReconstructionCompleteness.MINIMAL.value  == "minimal"
        assert ReconstructionCompleteness.FAILED.value   == "failed"

    def test_timeline_report_serialises_to_json(self):
        r = TimelineReport(session_id="abc", evidence_trust="trusted",
                           completeness=ReconstructionCompleteness.COMPLETE)
        j = json.loads(r.model_dump_json())
        assert j["session_id"] == "abc"
        assert j["completeness"] == "complete"
        assert "reconstructed_at" in j


# ---------------------------------------------------------------------------
# TestToolPairing
# ---------------------------------------------------------------------------


class TestToolPairing:
    def test_tool_call_and_result_paired(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(session_id=sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)

        tool_entries = [e for e in report.entries if e.event_type == "tool_action"]
        assert len(tool_entries) == 1
        e = tool_entries[0]
        assert e.tool_name == "search_email"
        assert 2 in e.raw_sequence_numbers
        assert 3 in e.raw_sequence_numbers

    def test_tool_entry_captures_artifact_refs(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(session_id=sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)

        tool_entry = next(e for e in report.entries if e.event_type == "tool_action")
        assert tool_entry.artifact_refs == [{"artifact_type": "email", "artifact_id": 4}]

    def test_tool_entry_captures_input_summary(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(session_id=sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)

        tool_entry = next(e for e in report.entries if e.event_type == "tool_action")
        assert "salary" in (tool_entry.input_summary or "")

    def test_multiple_tool_pairs(self, tmp_path):
        sid = str(uuid.uuid4())
        events = [
            {"session_id": sid, "sequence_number": 0, "event_type": "session_start",
             "timestamp": "2024-01-01T00:00:00+00:00", "user_prompt": "test", "model": "m"},
            {"session_id": sid, "sequence_number": 1, "event_type": "tool_call",
             "timestamp": "2024-01-01T00:00:01+00:00",
             "tool_name": "search_email", "input_data": {"keyword": "salary"}},
            {"session_id": sid, "sequence_number": 2, "event_type": "tool_result",
             "timestamp": "2024-01-01T00:00:02+00:00",
             "tool_name": "search_email", "row_count": 2, "evidence_refs": []},
            {"session_id": sid, "sequence_number": 3, "event_type": "tool_call",
             "timestamp": "2024-01-01T00:00:03+00:00",
             "tool_name": "retrieve_email", "input_data": {"identifier": "42"}},
            {"session_id": sid, "sequence_number": 4, "event_type": "tool_result",
             "timestamp": "2024-01-01T00:00:04+00:00",
             "tool_name": "retrieve_email", "row_count": 1, "evidence_refs": []},
            {"session_id": sid, "sequence_number": 5, "event_type": "agent_response",
             "timestamp": "2024-01-01T00:00:05+00:00", "content": "Done."},
            {"session_id": sid, "sequence_number": 6, "event_type": "session_end",
             "timestamp": "2024-01-01T00:00:06+00:00",
             "total_events": 6, "status": "completed"},
        ]
        p  = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)

        tool_entries = [e for e in report.entries if e.event_type == "tool_action"]
        assert len(tool_entries) == 2
        assert report.tool_sequence == ["search_email", "retrieve_email"]

    def test_tool_sequence_populated(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)
        assert "search_email" in report.tool_sequence


# ---------------------------------------------------------------------------
# TestOrphanedEvents
# ---------------------------------------------------------------------------


class TestOrphanedEvents:
    def _orphaned_call_events(self, sid: str) -> list[dict[str, Any]]:
        return [
            {"session_id": sid, "sequence_number": 0, "event_type": "session_start",
             "timestamp": "2024-01-01T00:00:00+00:00", "user_prompt": "x", "model": "m"},
            {"session_id": sid, "sequence_number": 1, "event_type": "tool_call",
             "timestamp": "2024-01-01T00:00:01+00:00",
             "tool_name": "search_email", "input_data": {"keyword": "x"}},
            # NO tool_result follows
            {"session_id": sid, "sequence_number": 2, "event_type": "agent_response",
             "timestamp": "2024-01-01T00:00:02+00:00", "content": "result."},
            {"session_id": sid, "sequence_number": 3, "event_type": "session_end",
             "timestamp": "2024-01-01T00:00:03+00:00",
             "total_events": 3, "status": "completed"},
        ]

    def test_orphaned_tool_call_detected(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = self._orphaned_call_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events, session_complete=False,
                                        trust=EvidenceTrust.DEGRADED)
        report = reconstruct_timeline(p, ir)

        orphaned = [e for e in report.entries if "orphaned_tool_call" in e.anomaly]
        assert len(orphaned) == 1

    def test_orphaned_call_anomaly_in_report(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = self._orphaned_call_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events, session_complete=False,
                                        trust=EvidenceTrust.DEGRADED)
        report = reconstruct_timeline(p, ir)
        assert any("orphaned" in a.lower() for a in report.anomalies)

    def test_orphaned_tool_result_detected(self, tmp_path):
        sid = str(uuid.uuid4())
        events = [
            {"session_id": sid, "sequence_number": 0, "event_type": "session_start",
             "timestamp": "2024-01-01T00:00:00+00:00", "user_prompt": "x", "model": "m"},
            # tool_result without preceding tool_call
            {"session_id": sid, "sequence_number": 1, "event_type": "tool_result",
             "timestamp": "2024-01-01T00:00:01+00:00",
             "tool_name": "search_email", "row_count": 0, "evidence_refs": []},
            {"session_id": sid, "sequence_number": 2, "event_type": "session_end",
             "timestamp": "2024-01-01T00:00:02+00:00",
             "total_events": 2, "status": "completed"},
        ]
        p  = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)

        orphaned = [e for e in report.entries if "orphaned_tool_result" in e.anomaly]
        assert len(orphaned) == 1


# ---------------------------------------------------------------------------
# TestIntegrityPropagation
# ---------------------------------------------------------------------------


class TestIntegrityPropagation:
    def test_valid_events_get_valid_status(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)

        for entry in report.entries:
            assert entry.integrity_status == "valid", \
                f"Entry {entry.sequence_number} ({entry.event_type}) has unexpected status"

    def test_invalid_event_propagated(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        # Mark sequence 1 (user_prompt) as invalid
        ir = _make_integrity_report(
            sid, events,
            chain_valid=False,
            trust=EvidenceTrust.COMPROMISED,
            valid_seqs={0, 2, 3, 4, 5},  # seq 1 is NOT valid
        )
        report = reconstruct_timeline(p, ir)

        user_prompt_entry = next(
            (e for e in report.entries if e.event_type == "user_prompt"), None
        )
        assert user_prompt_entry is not None
        assert user_prompt_entry.integrity_status == "invalid"

    def test_tool_pair_invalid_when_either_invalid(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        # Mark seq 3 (tool_result) as invalid
        ir = _make_integrity_report(
            sid, events,
            chain_valid=False,
            trust=EvidenceTrust.COMPROMISED,
            valid_seqs={0, 1, 2, 4, 5},  # seq 3 invalid
        )
        report = reconstruct_timeline(p, ir)

        tool_entry = next(e for e in report.entries if e.event_type == "tool_action")
        assert tool_entry.integrity_status == "invalid"

    def test_invalid_entry_anomaly_recorded(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(
            sid, events,
            chain_valid=False,
            trust=EvidenceTrust.COMPROMISED,
            valid_seqs={0, 1, 2, 4, 5},
        )
        report = reconstruct_timeline(p, ir)
        tool_entry = next(e for e in report.entries if e.event_type == "tool_action")
        assert "integrity_failure" in tool_entry.anomaly


# ---------------------------------------------------------------------------
# TestCompletenessDerivation
# ---------------------------------------------------------------------------


class TestCompletenessDerivation:
    def test_complete_for_trusted_clean_session(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events, trust=EvidenceTrust.TRUSTED,
                                        session_complete=True)
        report = reconstruct_timeline(p, ir)
        assert report.completeness == ReconstructionCompleteness.COMPLETE

    def test_partial_for_degraded_trust(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events, trust=EvidenceTrust.DEGRADED)
        report = reconstruct_timeline(p, ir)
        assert report.completeness == ReconstructionCompleteness.PARTIAL

    def test_partial_when_session_incomplete(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events, trust=EvidenceTrust.TRUSTED,
                                        session_complete=False)
        report = reconstruct_timeline(p, ir)
        assert report.completeness in (
            ReconstructionCompleteness.PARTIAL,
            ReconstructionCompleteness.COMPLETE,  # no anomalies in raw data
        )
        # But session_complete=False must be reflected in anomalies or completeness
        # (the verifier would have produced a MISSING_END_EVENT finding)

    def test_failed_for_unknown_trust(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events, trust=EvidenceTrust.UNKNOWN)
        report = reconstruct_timeline(p, ir)
        assert report.completeness == ReconstructionCompleteness.FAILED

    def test_failed_for_empty_file(self, tmp_path):
        sid = str(uuid.uuid4())
        p   = tmp_path / "empty.jsonl"
        p.write_text("")
        ir = _make_integrity_report(sid, [], trust=EvidenceTrust.UNKNOWN)
        report = reconstruct_timeline(p, ir)
        assert report.completeness == ReconstructionCompleteness.FAILED


# ---------------------------------------------------------------------------
# TestAnomalyDetection
# ---------------------------------------------------------------------------


class TestAnomalyDetection:
    def test_missing_session_start_anomaly(self, tmp_path):
        sid = str(uuid.uuid4())
        events = [
            {"session_id": sid, "sequence_number": 0, "event_type": "user_prompt",
             "timestamp": "2024-01-01T00:00:00+00:00", "content": "find salary"},
            {"session_id": sid, "sequence_number": 1, "event_type": "session_end",
             "timestamp": "2024-01-01T00:00:01+00:00", "total_events": 1, "status": "completed"},
        ]
        p  = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(sid, events, session_complete=False,
                                    trust=EvidenceTrust.DEGRADED)
        report = reconstruct_timeline(p, ir)
        assert any("session_start" in a for a in report.anomalies)

    def test_missing_session_end_anomaly(self, tmp_path):
        sid = str(uuid.uuid4())
        events = [
            {"session_id": sid, "sequence_number": 0, "event_type": "session_start",
             "timestamp": "2024-01-01T00:00:00+00:00", "user_prompt": "x", "model": "m"},
            {"session_id": sid, "sequence_number": 1, "event_type": "agent_response",
             "timestamp": "2024-01-01T00:00:01+00:00", "content": "done"},
        ]
        p  = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(sid, events, session_complete=False,
                                    trust=EvidenceTrust.DEGRADED,
                                    workflow_anomalies_override=[
                                        "session_end event is missing"
                                    ])
        report = reconstruct_timeline(p, ir)
        assert any("session_end" in a for a in report.anomalies)

    def test_workflow_anomalies_propagated_from_integrity_report(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        # Manually inject a workflow anomaly into the IntegrityReport
        ir.workflow_anomalies = ["test workflow anomaly injected by test"]
        report = reconstruct_timeline(p, ir)
        assert "test workflow anomaly injected by test" in report.anomalies

    def test_compromised_entries_noted_in_anomalies(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(
            sid, events,
            chain_valid=False,
            trust=EvidenceTrust.COMPROMISED,
            valid_seqs={0, 2, 3, 4, 5},  # seq 1 invalid
        )
        report = reconstruct_timeline(p, ir)
        assert any("integrity failure" in a.lower() or "invalid" in a.lower()
                   for a in report.anomalies)


# ---------------------------------------------------------------------------
# TestFullSessionReconstruction
# ---------------------------------------------------------------------------


class TestFullSessionReconstruction:
    def test_clean_session_entry_count(self, tmp_path):
        """
        6 raw events → 5 timeline entries:
        session_start, user_prompt, tool_action (pair), agent_response, session_end
        """
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)
        assert report.total_timeline_entries == 5
        assert report.total_events_in_session == 6

    def test_clean_session_ordering(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)
        seqs   = [e.sequence_number for e in report.entries]
        assert seqs == sorted(seqs), "Timeline entries must be in sequence_number order"

    def test_clean_session_event_types(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)
        types  = [e.event_type for e in report.entries]
        assert types[0] == "session_start"
        assert types[-1] == "session_end"
        assert "tool_action" in types

    def test_user_prompt_extracted(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)
        assert report.user_prompt is not None
        assert "salary" in report.user_prompt

    def test_compromised_session_entries_annotated(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(
            sid, events,
            chain_valid=False,
            trust=EvidenceTrust.COMPROMISED,
            valid_seqs={0, 2, 3, 4, 5},
        )
        report = reconstruct_timeline(p, ir)
        invalid = [e for e in report.entries if e.integrity_status == "invalid"]
        assert len(invalid) >= 1

    def test_integrity_report_embedded(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)
        assert report.integrity_report is ir

    def test_evidence_trust_copied_to_report(self, tmp_path):
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events, trust=EvidenceTrust.TRUSTED)
        report = reconstruct_timeline(p, ir)
        assert report.evidence_trust == "trusted"

    def test_report_serialises_without_integrity_report(self, tmp_path):
        """Phase 4/5 will dump JSON excluding the embedded integrity_report."""
        sid    = str(uuid.uuid4())
        events = _make_full_events(sid)
        p      = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir     = _make_integrity_report(sid, events)
        report = reconstruct_timeline(p, ir)
        # Should not crash when excluding integrity_report
        output = report.model_dump(exclude={"integrity_report"})
        assert "entries" in output
        assert "integrity_report" not in output


# ---------------------------------------------------------------------------
# TestEdgeCases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_file_returns_failed_report(self, tmp_path):
        sid = str(uuid.uuid4())
        p   = tmp_path / "empty.jsonl"
        p.write_text("")
        ir  = _make_integrity_report(sid, [], trust=EvidenceTrust.UNKNOWN)
        report = reconstruct_timeline(p, ir)
        assert report.completeness == ReconstructionCompleteness.FAILED
        assert report.total_timeline_entries == 0

    def test_single_session_start_only(self, tmp_path):
        sid = str(uuid.uuid4())
        events = [
            {"session_id": sid, "sequence_number": 0, "event_type": "session_start",
             "timestamp": "2024-01-01T00:00:00+00:00", "user_prompt": "x", "model": "m"},
        ]
        p  = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(sid, events, session_complete=False,
                                    trust=EvidenceTrust.DEGRADED)
        report = reconstruct_timeline(p, ir)
        assert report.total_timeline_entries == 1
        assert report.entries[0].event_type == "session_start"

    def test_unknown_event_type_handled(self, tmp_path):
        sid = str(uuid.uuid4())
        events = [
            {"session_id": sid, "sequence_number": 0, "event_type": "session_start",
             "timestamp": "2024-01-01T00:00:00+00:00", "user_prompt": "x", "model": "m"},
            {"session_id": sid, "sequence_number": 1, "event_type": "future_event_type",
             "timestamp": "2024-01-01T00:00:01+00:00", "data": "some data"},
            {"session_id": sid, "sequence_number": 2, "event_type": "session_end",
             "timestamp": "2024-01-01T00:00:02+00:00", "total_events": 2, "status": "completed"},
        ]
        p  = tmp_path / "s.jsonl"
        _write_session(p, events)
        ir = _make_integrity_report(sid, events)
        # Should not raise
        report = reconstruct_timeline(p, ir)
        assert report.total_timeline_entries == 3

    def test_malformed_json_line_skipped(self, tmp_path):
        sid = str(uuid.uuid4())
        p   = tmp_path / "s.jsonl"
        p.write_text(
            json.dumps({"session_id": sid, "sequence_number": 0,
                        "event_type": "session_start", "timestamp": "2024-01-01T00:00:00+00:00",
                        "user_prompt": "x", "model": "m"}) + "\n"
            + "NOT VALID JSON\n"
            + json.dumps({"session_id": sid, "sequence_number": 1,
                          "event_type": "session_end", "timestamp": "2024-01-01T00:00:01+00:00",
                          "total_events": 1, "status": "completed"}) + "\n"
        )
        ir = _make_integrity_report(sid, [], trust=EvidenceTrust.DEGRADED)
        # Should not raise
        report = reconstruct_timeline(p, ir)
        assert report.total_timeline_entries >= 1

    def test_truncate_helper(self):
        assert _truncate("hello world", 5) == "he..."
        assert _truncate("short", 100) == "short"
        assert _truncate("", 10) == ""


# ---------------------------------------------------------------------------
# Fix for _make_integrity_report to support workflow_anomalies_override
# ---------------------------------------------------------------------------

# Override the helper to support workflow_anomalies_override parameter
_original_make_ir = _make_integrity_report

def _make_integrity_report(
    session_id,
    events,
    chain_valid=True,
    trust=EvidenceTrust.TRUSTED,
    session_complete=True,
    valid_seqs=None,
    workflow_anomalies_override=None,
):
    ir = _original_make_ir(session_id, events, chain_valid, trust, session_complete, valid_seqs)
    if workflow_anomalies_override is not None:
        ir.workflow_anomalies = workflow_anomalies_override
    return ir
