"""
AFEM Phase 2 — Integrity Manager Test Suite
=============================================
Tests for:
  - integrity.hash_chain  (primitives)
  - integrity.sealer      (sealing)
  - integrity.verifier    (verification and report generation)

All tests are self-contained and use only tmp_path fixtures — no dependency
on the real mailbox.db, real evidence files, or the LangGraph agent.

Run:
    python -m pytest tests/test_integrity.py -v

Organisation:
    TestCanonicalJSON        — determinism and key-ordering guarantees
    TestComputeEventHash     — hash correctness and sensitivity
    TestChainEvents          — chain construction correctness
    TestIsSealed             — file state detection
    TestSealer               — end-to-end sealing, idempotency, atomicity
    TestVerifier             — clean chain, modification, deletion, insertion,
                               reordering, gap detection, sequence anomalies
    TestIntegrityReport      — schema, verdict property, JSON serialisation
    TestSealerVerifierRoundtrip — property: seal then verify always passes
"""
from __future__ import annotations

import copy
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from schemas import report

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest

from integrity.hash_chain import (
    GENESIS_HASH,
    canonical_json,
    chain_events,
    compute_event_hash,
    is_sealed,
    read_jsonl,
    write_jsonl,
)
from integrity.sealer import SealingError, seal_session
from integrity.verifier import verify_session
from schemas.integrity import IntegrityReport, VerificationResult, EvidenceTrust, FindingType


# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------

def _make_events(n: int = 4, session_id: str | None = None) -> list[dict[str, Any]]:
    """
    Create n minimal event dicts without hash fields, simulating a raw
    session JSONL produced by EvidenceCollector before sealing.
    """
    sid = session_id or str(uuid.uuid4())
    event_types = [
        "session_start", "user_prompt", "tool_call",
        "tool_result", "agent_response", "session_end",
    ]
    return [
        {
            "session_id":      sid,
            "sequence_number": i,
            "event_type":      event_types[i % len(event_types)],
            "timestamp":       f"2024-01-01T00:0{i}:00Z",
            "content":         f"event content {i}",
        }
        for i in range(n)
    ]


def _write_raw_session(path: Path, n: int = 4) -> list[dict[str, Any]]:
    """Write n unsealed events to path and return the dicts."""
    events = _make_events(n)
    write_jsonl(events, path)
    return events


def _write_sealed_session(path: Path, n: int = 4) -> list[dict[str, Any]]:
    """Write n events to path, seal them, and return the post-chain dicts."""
    _write_raw_session(path, n)
    seal_session(path)
    return list(read_jsonl(path))


# ---------------------------------------------------------------------------
# TestCanonicalJSON
# ---------------------------------------------------------------------------

class TestCanonicalJSON:
    def test_output_is_bytes(self):
        assert isinstance(canonical_json({"a": 1}), bytes)

    def test_keys_sorted(self):
        result = canonical_json({"z": 1, "a": 2, "m": 3})
        parsed = json.loads(result)
        assert list(parsed.keys()) == ["a", "m", "z"]

    def test_no_whitespace(self):
        result = canonical_json({"key": "value"}).decode()
        assert " " not in result
        assert "\n" not in result

    def test_deterministic_across_calls(self):
        d = {"b": [1, 2], "a": {"x": True}}
        assert canonical_json(d) == canonical_json(d)

    def test_dict_order_does_not_matter(self):
        d1 = {"a": 1, "b": 2}
        d2 = {"b": 2, "a": 1}
        assert canonical_json(d1) == canonical_json(d2)

    def test_unicode_preserved(self):
        result = canonical_json({"emoji": "🔒"}).decode("utf-8")
        assert "🔒" in result

    def test_nested_dict_keys_sorted(self):
        d = {"outer": {"z": 1, "a": 2}}
        result = json.loads(canonical_json(d))
        assert list(result["outer"].keys()) == ["a", "z"]


# ---------------------------------------------------------------------------
# TestComputeEventHash
# ---------------------------------------------------------------------------

class TestComputeEventHash:
    def _base_event(self) -> dict[str, Any]:
        return {
            "session_id":      "test-session",
            "sequence_number": 0,
            "event_type":      "user_prompt",
            "previous_hash":   GENESIS_HASH,
            "content":         "find payroll emails",
        }

    def test_returns_64_char_hex(self):
        h = compute_event_hash(self._base_event())
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self):
        e = self._base_event()
        assert compute_event_hash(e) == compute_event_hash(e)

    def test_sensitive_to_content_change(self):
        e1 = self._base_event()
        e2 = {**e1, "content": "different content"}
        assert compute_event_hash(e1) != compute_event_hash(e2)

    def test_sensitive_to_previous_hash_change(self):
        e1 = self._base_event()
        e2 = {**e1, "previous_hash": "a" * 64}
        assert compute_event_hash(e1) != compute_event_hash(e2)

    def test_sensitive_to_sequence_number_change(self):
        e1 = self._base_event()
        e2 = {**e1, "sequence_number": 99}
        assert compute_event_hash(e1) != compute_event_hash(e2)

    def test_genesis_hash_is_all_zeros(self):
        assert GENESIS_HASH == "0" * 64


# ---------------------------------------------------------------------------
# TestChainEvents
# ---------------------------------------------------------------------------

class TestChainEvents:
    def test_adds_previous_hash_and_event_hash(self):
        events = _make_events(3)
        chained = chain_events(events)
        for e in chained:
            assert "previous_hash" in e
            assert "event_hash"    in e

    def test_first_event_uses_genesis_hash(self):
        events  = _make_events(1)
        chained = chain_events(events)
        assert chained[0]["previous_hash"] == GENESIS_HASH

    def test_chain_links_correctly(self):
        events  = _make_events(4)
        chained = chain_events(events)
        for i in range(1, len(chained)):
            assert chained[i]["previous_hash"] == chained[i - 1]["event_hash"]

    def test_returns_same_list(self):
        events  = _make_events(3)
        original_ids = [id(e) for e in events]
        result  = chain_events(events)
        assert [id(e) for e in result] == original_ids

    def test_strips_existing_hash_fields(self):
        """Calling chain_events twice must not double-corrupt the chain."""
        events    = _make_events(3)
        chained1  = chain_events(copy.deepcopy(events))
        # Calling again on already-chained events should produce same result.
        chained2  = chain_events(copy.deepcopy(chained1))
        assert chained1[0]["event_hash"] == chained2[0]["event_hash"]

    def test_each_hash_is_unique(self):
        events  = _make_events(5)
        chained = chain_events(events)
        hashes  = [e["event_hash"] for e in chained]
        assert len(set(hashes)) == len(hashes)

    def test_empty_list_returns_empty(self):
        assert chain_events([]) == []


# ---------------------------------------------------------------------------
# TestIsSealed
# ---------------------------------------------------------------------------

class TestIsSealed:
    def test_unsealed_file_returns_false(self, tmp_path):
        p = tmp_path / "session.jsonl"
        write_jsonl(_make_events(2), p)
        assert is_sealed(p) is False

    def test_sealed_file_returns_true(self, tmp_path):
        p = tmp_path / "session.jsonl"
        _write_sealed_session(p, n=2)
        assert is_sealed(p) is True

    def test_nonexistent_file_returns_false(self, tmp_path):
        assert is_sealed(tmp_path / "missing.jsonl") is False

    def test_empty_file_returns_false(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("")
        assert is_sealed(p) is False


# ---------------------------------------------------------------------------
# TestSealer
# ---------------------------------------------------------------------------

class TestSealer:
    def test_seal_adds_hash_fields(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_raw_session(p)
        seal_session(p)
        for event in read_jsonl(p):
            assert "event_hash"    in event
            assert "previous_hash" in event

    def test_seal_returns_true_for_new_seal(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_raw_session(p)
        assert seal_session(p) is True

    def test_seal_returns_false_for_already_sealed(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_raw_session(p)
        seal_session(p)
        assert seal_session(p) is False

    def test_seal_is_idempotent(self, tmp_path):
        """Sealing twice must produce identical files."""
        p = tmp_path / "s.jsonl"
        _write_raw_session(p)
        seal_session(p)
        events_after_first = list(read_jsonl(p))
        seal_session(p)  # no-op
        events_after_second = list(read_jsonl(p))
        assert events_after_first == events_after_second

    def test_sealed_file_is_valid_chain(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=6)
        report = verify_session(p)
        assert report.chain_valid

    def test_original_fields_preserved(self, tmp_path):
        p = tmp_path / "s.jsonl"
        originals = _write_raw_session(p, n=3)
        seal_session(p)
        sealed = list(read_jsonl(p))
        for orig, sealed_e in zip(originals, sealed):
            for key, value in orig.items():
                assert sealed_e[key] == value

    def test_seal_raises_on_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            seal_session(tmp_path / "nonexistent.jsonl")

    def test_seal_raises_on_empty_file(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("")
        with pytest.raises(SealingError):
            seal_session(p)

    def test_event_count_unchanged_after_sealing(self, tmp_path):
        p = tmp_path / "s.jsonl"
        raw = _write_raw_session(p, n=5)
        seal_session(p)
        sealed = list(read_jsonl(p))
        assert len(sealed) == len(raw)

    def test_first_event_previous_hash_is_genesis(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p)
        first = next(read_jsonl(p))
        assert first["previous_hash"] == GENESIS_HASH

    def test_chain_linkage_after_seal(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=5)
        events = list(read_jsonl(p))
        for i in range(1, len(events)):
            assert events[i]["previous_hash"] == events[i - 1]["event_hash"]


# ---------------------------------------------------------------------------
# TestVerifier — clean chain
# ---------------------------------------------------------------------------

class TestVerifier:
    def test_verify_clean_chain_passes(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=4)
        report = verify_session(p)
        assert report.chain_valid
        assert report.verdict == "VERIFIED"

    def test_verify_all_events_valid(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=4)
        report = verify_session(p)
        assert all(r.is_valid for r in report.events)

    def test_verify_no_tamper_evidence(self, tmp_path):
        """
        A session built by _make_events lacks session_end, so the enhanced
        verifier correctly reports MISSING_END_EVENT. This test confirms
        the hash chain itself is clean even when structural anomalies exist.
        """
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=4)
        report = verify_session(p)
        # Hash chain must be valid even though workflow anomalies exist.
        assert report.chain_valid
        # No hash-chain findings — only structural findings (missing session_end).
        hash_failures = [
            f for f in report.findings
            if f.finding_type.value in ("content_hash_mismatch", "chain_link_mismatch")
        ]
        assert hash_failures == []

    def test_report_total_events_correct(self, tmp_path):
        p = tmp_path / "s.jsonl"
        n = 6
        _write_sealed_session(p, n=n)
        report = verify_session(p)
        assert report.total_events == n

    def test_genesis_hash_in_report(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=3)
        events = list(read_jsonl(p))
        report = verify_session(p)
        assert report.genesis_hash == events[0]["event_hash"]

    def test_terminal_hash_in_report(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=3)
        events = list(read_jsonl(p))
        report = verify_session(p)
        assert report.terminal_hash == events[-1]["event_hash"]

    def test_first_broken_seq_is_none_when_clean(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=3)
        report = verify_session(p)
        assert report.first_broken_seq is None


# ---------------------------------------------------------------------------
# TestVerifier — tamper detection
# ---------------------------------------------------------------------------

class TestVerifierTamperDetection:
    def _tamper_event(
        self,
        path: Path,
        seq: int,
        field: str,
        new_value: Any,
    ) -> None:
        """Modify one field of one event in a sealed JSONL file."""
        events = list(read_jsonl(path))
        target = next(e for e in events if e["sequence_number"] == seq)
        target[field] = new_value
        write_jsonl(events, path)

    def test_modification_detected(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=4)
        self._tamper_event(p, seq=1, field="content", new_value="TAMPERED")
        report = verify_session(p)
        assert not report.chain_valid
        assert report.verdict == "FAILED"

    def test_modification_first_broken_seq_correct(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=4)
        self._tamper_event(p, seq=2, field="content", new_value="MODIFIED")
        report = verify_session(p)
        assert report.first_broken_seq == 2

    def test_deletion_detected(self, tmp_path):
        """Remove one event from a sealed file."""
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=5)
        events = list(read_jsonl(p))
        # Delete event with sequence_number=2
        events = [e for e in events if e["sequence_number"] != 2]
        write_jsonl(events, p)
        report = verify_session(p)
        # Either chain breaks at seq 3 (previous_hash mismatch) or gap is detected
        assert not report.chain_valid or len(report.tamper_evidence) > 0

    def test_deletion_sequence_gap_recorded(self, tmp_path):
        """Deleting an event must leave a gap in tamper_evidence."""
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=5)
        events = list(read_jsonl(p))
        events = [e for e in events if e["sequence_number"] != 2]
        write_jsonl(events, p)
        report = verify_session(p)
        gap_msgs = [msg for msg in report.tamper_evidence if "missing" in msg or "gap" in msg]
        assert len(gap_msgs) > 0

    def test_insertion_detected(self, tmp_path):
        """Insert a fake event into a sealed file."""
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=4)
        events = list(read_jsonl(p))
        fake   = {
            "session_id":      events[0]["session_id"],
            "sequence_number": 99,
            "event_type":      "tool_call",
            "timestamp":       "2024-01-01T99:00:00Z",
            "content":         "injected event",
            "previous_hash":   GENESIS_HASH,
            "event_hash":      "a" * 64,
        }
        events.append(fake)
        events.sort(key=lambda e: e["sequence_number"])
        write_jsonl(events, p)
        report = verify_session(p)
        # Inserted event with wrong hashes must fail
        invalid = [r for r in report.events if not r.is_valid]
        assert len(invalid) > 0

    def test_reordering_detected(self, tmp_path):
        """
        True event reordering: swap the full content of two events INCLUDING
        their sequence_number fields, so the sequence numbers in the chain
        don't match the payload order any more.

        Note: swapping only file line positions (not sequence_numbers) is
        detected via the sequence-gap path, not the hash-chain path, because
        the verifier re-sorts by sequence_number before verification.
        Swapping sequence_number fields is the realistic attack where an
        adversary re-numbers events to hide the reordering.
        """
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=5)
        events = list(read_jsonl(p))
        # Swap the sequence_number fields of events 1 and 2 — simulates an
        # adversary re-numbering to disguise swapped content order.
        events[1]["sequence_number"], events[2]["sequence_number"] = (
            events[2]["sequence_number"],
            events[1]["sequence_number"],
        )
        write_jsonl(events, p)
        report = verify_session(p)
        # After re-sort, events are now in the wrong payload order relative
        # to their previous_hash chain — so the chain must fail.
        assert not report.chain_valid

    def test_hash_field_tampering_detected(self, tmp_path):
        """Directly overwrite event_hash with garbage."""
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=3)
        self._tamper_event(p, seq=0, field="event_hash", new_value="b" * 64)
        report = verify_session(p)
        assert not report.chain_valid

    def test_verify_raises_on_nonexistent_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            verify_session(tmp_path / "missing.jsonl")

    def test_verify_raises_on_empty_file(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("")
        with pytest.raises(ValueError):
            verify_session(p)


# ---------------------------------------------------------------------------
# TestIntegrityReport — schema and serialisation
# ---------------------------------------------------------------------------

class TestIntegrityReport:
    def test_verdict_verified(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=3)
        report = verify_session(p)
        assert report.verdict == "VERIFIED"

    def test_verdict_failed(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=3)
        events = list(read_jsonl(p))
        events[1]["content"] = "tampered"
        write_jsonl(events, p)
        report = verify_session(p)
        assert report.verdict == "FAILED"

    def test_report_serialises_to_json(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=3)
        report = verify_session(p)
        json_str = report.model_dump_json()
        parsed   = json.loads(json_str)
        assert "session_id"    in parsed
        assert "chain_valid"   in parsed
        assert "total_events"  in parsed
        assert "genesis_hash"  in parsed
        assert "terminal_hash" in parsed
        assert "events"        in parsed
        assert "tamper_evidence" in parsed

    def test_verification_result_has_all_fields(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=2)
        report = verify_session(p)
        r = report.events[0]
        assert hasattr(r, "sequence_number")
        assert hasattr(r, "event_type")
        assert hasattr(r, "is_valid")
        assert hasattr(r, "expected_prev")
        assert hasattr(r, "actual_prev")
        assert hasattr(r, "expected_hash")
        assert hasattr(r, "actual_hash")
        assert hasattr(r, "failure_reason")

    def test_session_id_in_report(self, tmp_path):
        sid = str(uuid.uuid4())
        events = _make_events(3, session_id=sid)
        p = tmp_path / f"{sid}.jsonl"
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        assert report.session_id == sid


# ---------------------------------------------------------------------------
# TestSealerVerifierRoundtrip — property tests
# ---------------------------------------------------------------------------

class TestSealerVerifierRoundtrip:
    """
    Property: for any valid unsealed session, seal then verify must always
    return chain_valid=True. If this ever fails, it is a bug in either the
    sealer or the verifier.
    """

    @pytest.mark.parametrize("n_events", [1, 2, 4, 8, 16])
    def test_roundtrip_always_passes(self, tmp_path, n_events):
        p = tmp_path / "s.jsonl"
        _write_sealed_session(p, n=n_events)
        report = verify_session(p)
        assert report.chain_valid, (
            f"Roundtrip failed for n_events={n_events}: {report.tamper_evidence}"
        )

    def test_roundtrip_with_unicode_content(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_events(3)
        events[1]["content"] = "Ünïcödé cöntënt 🔒 — forensics"
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        assert report.chain_valid

    def test_roundtrip_with_nested_dict_content(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_events(3)
        events[1]["output_data"] = {
            "count": 2,
            "evidence_refs": [
                {"artifact_type": "email", "artifact_id": 4},
                {"artifact_type": "email", "artifact_id": 7},
            ],
        }
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        assert report.chain_valid

# ===========================================================================
# Phase 2 Hardening — Extended Test Suite
# ===========================================================================
# The following test classes cover all new validation checks introduced in
# the hardened verifier: structural checks, workflow validation, timestamp
# anomaly detection, session-end cross-check, finding types, evidence trust
# derivation, and the investigator-facing CLI.
# ===========================================================================

from schemas.integrity import (
    EvidenceTrust,
    FindingType,
    ForensicFinding,
    Severity,
)


# ---------------------------------------------------------------------------
# Helper: build a structurally complete session (for tests needing TRUSTED)
# ---------------------------------------------------------------------------


def _make_full_session(
    session_id: str | None = None,
    n_tool_pairs: int = 1,
) -> list[dict[str, Any]]:
    """
    Build a complete, valid AFEM session with the correct workflow:
    session_start → user_prompt → [tool_call → tool_result]* →
    agent_response → session_end

    total_events in session_end is set correctly so session_complete=True.
    """
    sid  = session_id or str(uuid.uuid4())
    evts = []
    seq  = 0

    evts.append({
        "session_id": sid, "sequence_number": seq, "event_type": "session_start",
        "timestamp": "2024-06-01T10:00:00+00:00",
        "user_prompt": "Find payroll emails", "model": "test-model",
    }); seq += 1

    evts.append({
        "session_id": sid, "sequence_number": seq, "event_type": "user_prompt",
        "timestamp": "2024-06-01T10:00:01+00:00",
        "content": "Find payroll emails",
    }); seq += 1

    for i in range(n_tool_pairs):
        evts.append({
            "session_id": sid, "sequence_number": seq, "event_type": "tool_call",
            "timestamp": f"2024-06-01T10:00:{seq:02d}+00:00",
            "tool_name": "search_email", "input_data": {"keyword": "payroll"},
        }); seq += 1
        evts.append({
            "session_id": sid, "sequence_number": seq, "event_type": "tool_result",
            "timestamp": f"2024-06-01T10:00:{seq:02d}+00:00",
            "tool_name": "search_email", "output_data": {"count": 2}, "row_count": 2,
        }); seq += 1

    evts.append({
        "session_id": sid, "sequence_number": seq, "event_type": "agent_response",
        "timestamp": f"2024-06-01T10:00:{seq:02d}+00:00",
        "content": "Found payroll emails.",
    }); seq += 1

    # total_events = events before this one = seq
    evts.append({
        "session_id": sid, "sequence_number": seq, "event_type": "session_end",
        "timestamp": f"2024-06-01T10:00:{seq:02d}+00:00",
        "total_events": seq, "status": "completed",
    })

    return evts


def _sealed_full_session(path: Path, **kwargs) -> list[dict[str, Any]]:
    events = _make_full_session(**kwargs)
    write_jsonl(events, path)
    seal_session(path)
    return events


# ---------------------------------------------------------------------------
# TestEvidenceTrust — trust derivation
# ---------------------------------------------------------------------------


class TestEvidenceTrust:
    def test_trusted_for_clean_complete_session(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        assert report.evidence_trust == EvidenceTrust.TRUSTED

    def test_compromised_when_hash_fails(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        events[2]["content"] = "TAMPERED"
        write_jsonl(events, p)
        report = verify_session(p)
        assert report.evidence_trust == EvidenceTrust.COMPROMISED

    def test_degraded_when_session_incomplete(self, tmp_path):
        """A sealed session without session_end is DEGRADED (not COMPROMISED)."""
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        # Remove session_end
        events = [e for e in events if e["event_type"] != "session_end"]
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        assert report.chain_valid           # hash chain is still valid
        assert report.session_complete is False
        assert report.evidence_trust == EvidenceTrust.DEGRADED

    def test_degraded_when_workflow_anomaly_only(self, tmp_path):
        """Workflow anomaly without hash failure → DEGRADED not COMPROMISED."""
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        # Remove session_end so there's a workflow anomaly but no hash failure
        events = [e for e in events if e["event_type"] != "session_end"]
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        assert report.evidence_trust == EvidenceTrust.DEGRADED

    def test_trusted_requires_all_conditions(self, tmp_path):
        """TRUSTED only when: chain_valid AND session_complete AND no findings."""
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        assert report.chain_valid
        assert report.session_complete
        assert report.findings == []
        assert report.evidence_trust == EvidenceTrust.TRUSTED


# ---------------------------------------------------------------------------
# TestStructuredFindings — FindingType and Severity on VerificationResult
# ---------------------------------------------------------------------------


class TestStructuredFindings:
    def test_content_hash_mismatch_finding_type(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        events[1]["content"] = "MODIFIED"
        write_jsonl(events, p)
        report = verify_session(p)
        hash_findings = [
            f for f in report.findings
            if f.finding_type == FindingType.CONTENT_HASH_MISMATCH
        ]
        assert len(hash_findings) >= 1
        assert hash_findings[0].severity == Severity.CRITICAL

    def test_verification_result_carries_finding_type(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        events[2]["tool_name"] = "INJECTED"
        write_jsonl(events, p)
        report = verify_session(p)
        broken = next(r for r in report.events if not r.is_valid)
        assert broken.finding_type == FindingType.CONTENT_HASH_MISMATCH
        assert broken.severity     == Severity.CRITICAL

    def test_verified_events_have_no_finding_type(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        for ev in report.events:
            assert ev.finding_type is None
            assert ev.severity     is None

    def test_has_critical_findings_property(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        events[1]["content"] = "TAMPERED"
        write_jsonl(events, p)
        report = verify_session(p)
        assert report.has_critical_findings
        assert report.critical_finding_count >= 1

    def test_highest_severity_property(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        events[1]["content"] = "TAMPERED"
        write_jsonl(events, p)
        report = verify_session(p)
        assert report.highest_severity == Severity.CRITICAL

    def test_clean_session_highest_severity_is_none(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        assert report.highest_severity is None


# ---------------------------------------------------------------------------
# TestSessionEndValidation
# ---------------------------------------------------------------------------


class TestSessionEndValidation:
    def test_missing_session_end_detected(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        events = [e for e in events if e["event_type"] != "session_end"]
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        assert report.session_complete is False
        end_findings = [f for f in report.findings if f.finding_type == FindingType.MISSING_END_EVENT]
        assert len(end_findings) == 1

    def test_total_events_mismatch_detected(self, tmp_path):
        """Inserting an extra event without updating total_events."""
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        # Corrupt total_events in session_end (claims fewer events than exist)
        end = next(e for e in events if e["event_type"] == "session_end")
        end["total_events"] = 0  # claim 0 events before end
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        assert report.session_complete is False
        mismatch = [
            f for f in report.findings
            if f.finding_type in (
                FindingType.TOTAL_EVENTS_MISMATCH,
                FindingType.TRUNCATED_SESSION,
            )
        ]
        assert len(mismatch) >= 1

    def test_truncated_session_detected(self, tmp_path):
        """session_end declares more events than are actually present."""
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        end = next(e for e in events if e["event_type"] == "session_end")
        end["total_events"] = 999  # claim far more events than exist
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        assert report.session_complete is False
        truncated = [f for f in report.findings if f.finding_type == FindingType.TRUNCATED_SESSION]
        assert len(truncated) >= 1

    def test_correct_session_end_sets_complete(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        assert report.session_complete is True


# ---------------------------------------------------------------------------
# TestWorkflowValidation
# ---------------------------------------------------------------------------


class TestWorkflowValidation:
    def test_session_start_not_first_detected(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        # Move session_start to seq 1 and shift others
        start = events.pop(0)
        events.insert(1, start)
        for i, e in enumerate(events):
            e["sequence_number"] = i
        # Update total_events
        end = next(e for e in events if e["event_type"] == "session_end")
        end["total_events"] = len(events) - 1
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        wf = [f for f in report.findings if f.finding_type == FindingType.WORKFLOW_ANOMALY]
        assert len(wf) >= 1
        assert any("session_start" in f.message for f in wf)

    def test_tool_call_without_tool_result_detected(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_full_session(n_tool_pairs=2)
        # Remove one tool_result
        tool_results = [e for e in events if e["event_type"] == "tool_result"]
        events.remove(tool_results[0])
        for i, e in enumerate(events):
            e["sequence_number"] = i
        end = next(e for e in events if e["event_type"] == "session_end")
        end["total_events"] = len(events) - 1
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        wf = [f for f in report.findings if f.finding_type == FindingType.WORKFLOW_ANOMALY]
        assert any("tool_call" in f.message and "tool_result" in f.message for f in wf)

    def test_workflow_anomalies_list_populated(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        events = [e for e in events if e["event_type"] != "session_end"]
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        # Missing session_end → workflow anomaly
        assert len(report.workflow_anomalies) >= 1


# ---------------------------------------------------------------------------
# TestMissingFields
# ---------------------------------------------------------------------------


class TestMissingFields:
    def test_missing_sequence_number_detected(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        del events[2]["sequence_number"]
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        missing = [f for f in report.findings if f.finding_type == FindingType.MISSING_FIELD]
        assert len(missing) >= 1

    def test_missing_event_hash_after_seal(self, tmp_path):
        """Deleting event_hash from a sealed file → MISSING_FIELD + chain failure."""
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        del events[2]["event_hash"]
        write_jsonl(events, p)
        report = verify_session(p)
        missing = [f for f in report.findings if f.finding_type == FindingType.MISSING_FIELD]
        assert len(missing) >= 1

    def test_missing_previous_hash_after_seal(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        del events[3]["previous_hash"]
        write_jsonl(events, p)
        report = verify_session(p)
        missing = [f for f in report.findings if f.finding_type == FindingType.MISSING_FIELD]
        assert len(missing) >= 1


# ---------------------------------------------------------------------------
# TestCorruptedJSON
# ---------------------------------------------------------------------------


class TestCorruptedJSON:
    def test_single_corrupt_line_detected(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        write_jsonl(events, p)
        seal_session(p)
        # Corrupt one line in the sealed file
        lines = p.read_text().splitlines()
        lines[2] = "NOT VALID JSON {{{{"
        p.write_text("\n".join(lines) + "\n")
        report = verify_session(p)
        corrupt = [f for f in report.findings if f.finding_type == FindingType.CORRUPTED_JSON]
        assert len(corrupt) >= 1

    def test_corrupt_file_does_not_crash_verifier(self, tmp_path):
        p = tmp_path / "bad.jsonl"
        p.write_text(
            "{invalid json}\n{also bad}\n",
            encoding="utf-8",
        )

        # The verifier should handle malformed JSON gracefully and return
        # a structured forensic report instead of raising an exception.
        report = verify_session(p)

        assert report.chain_valid is False
        assert report.evidence_trust == EvidenceTrust.UNKNOWN
        assert report.total_events == 0

        assert any(
            finding.finding_type == FindingType.CORRUPTED_JSON
            for finding in report.findings
        )

    def test_partial_corruption_still_verifies_valid_lines(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        write_jsonl(events, p)
        seal_session(p)
        lines = p.read_text().splitlines()
        lines[1] = "THIS IS NOT JSON"
        p.write_text("\n".join(lines) + "\n")
        # Should not raise; should return a report with corrupt findings
        report = verify_session(p)
        assert isinstance(report, __import__("schemas.integrity", fromlist=["IntegrityReport"]).IntegrityReport)
        corrupt = [f for f in report.findings if f.finding_type == FindingType.CORRUPTED_JSON]
        assert len(corrupt) >= 1


# ---------------------------------------------------------------------------
# TestSessionMismatch
# ---------------------------------------------------------------------------


class TestSessionMismatch:
    def test_mixed_session_ids_detected(self, tmp_path):
        p = tmp_path / "s.jsonl"
        sid_a = str(uuid.uuid4())
        sid_b = str(uuid.uuid4())
        events_a = _make_full_session(session_id=sid_a)
        events_b = _make_full_session(session_id=sid_b)
        # Write a valid single-session file first, then manually inject a foreign event.
        write_jsonl(events_a, p)
        seal_session(p)
        # Append one event with a different session_id (post-seal contamination).
        contaminated = list(read_jsonl(p))
        contaminated.append({
            "session_id":      sid_b,
            "sequence_number": 999,
            "event_type":      "user_prompt",
            "timestamp":       "2024-12-01T00:00:00+00:00",
            "content":         "injected from another session",
            "previous_hash":   "0" * 64,
            "event_hash":      "a" * 64,
        })
        write_jsonl(contaminated, p)
        report = verify_session(p)
        mismatch = [f for f in report.findings if f.finding_type == FindingType.SESSION_MISMATCH]
        assert len(mismatch) >= 1
        assert mismatch[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# TestTimestampAnomaly
# ---------------------------------------------------------------------------


class TestTimestampAnomaly:
    def test_reversed_timestamps_detected(self, tmp_path):
        p = tmp_path / "s.jsonl"
        events = _make_full_session()
        # Set event 3's timestamp earlier than event 2's
        events[3]["timestamp"] = "2024-06-01T09:00:00+00:00"  # earlier than event 2
        write_jsonl(events, p)
        seal_session(p)
        report = verify_session(p)
        ts_findings = [f for f in report.findings if f.finding_type == FindingType.TIMESTAMP_ANOMALY]
        assert len(ts_findings) >= 1

    def test_monotonic_timestamps_no_anomaly(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        ts_findings = [f for f in report.findings if f.finding_type == FindingType.TIMESTAMP_ANOMALY]
        assert ts_findings == []


# ---------------------------------------------------------------------------
# TestIntegrityReportNewFields
# ---------------------------------------------------------------------------


class TestIntegrityReportNewFields:
    def test_verified_at_is_present(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        assert report.verified_at
        # Must be parseable as ISO-8601
        from datetime import datetime
        datetime.fromisoformat(report.verified_at)

    def test_first_failure_type_none_when_clean(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        assert report.first_failure_type is None

    def test_first_failure_type_set_when_compromised(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        events[1]["content"] = "TAMPERED"
        write_jsonl(events, p)
        report = verify_session(p)
        assert report.first_failure_type is not None

    def test_findings_list_serialises_to_json(self, tmp_path):
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        events = list(read_jsonl(p))
        events[2]["content"] = "TAMPERED"
        write_jsonl(events, p)
        report = verify_session(p)
        json_str = report.model_dump_json()
        parsed   = json.loads(json_str)
        assert "findings" in parsed
        assert isinstance(parsed["findings"], list)
        assert "evidence_trust" in parsed
        assert "verified_at" in parsed
        assert "session_complete" in parsed
        assert "workflow_anomalies" in parsed

    def test_clean_report_all_phases_fields_present(self, tmp_path):
        """Confirm all Phase 3–5 contract fields are present in a clean report."""
        p = tmp_path / "s.jsonl"
        _sealed_full_session(p)
        report = verify_session(p)
        # Phase 3 fields
        assert hasattr(report, "evidence_trust")
        assert hasattr(report, "session_complete")
        # Phase 4 fields
        assert hasattr(report, "workflow_anomalies")
        assert hasattr(report, "first_failure_type")
        assert hasattr(report, "findings")
        # Phase 5 fields
        assert hasattr(report, "verified_at")
        assert hasattr(report, "verdict")
        assert hasattr(report, "genesis_hash")
        assert hasattr(report, "terminal_hash")


# ---------------------------------------------------------------------------
# TestFindingSeverityDefaults
# ---------------------------------------------------------------------------


class TestFindingSeverityDefaults:
    def test_all_finding_types_have_severity_defaults(self):
        from schemas.integrity import FINDING_SEVERITY
        for ft in FindingType:
            assert ft in FINDING_SEVERITY, f"Missing severity default for {ft}"

    def test_hash_failures_are_critical(self):
        from schemas.integrity import FINDING_SEVERITY
        assert FINDING_SEVERITY[FindingType.CONTENT_HASH_MISMATCH] == Severity.CRITICAL
        assert FINDING_SEVERITY[FindingType.CHAIN_LINK_MISMATCH]   == Severity.CRITICAL
        assert FINDING_SEVERITY[FindingType.SESSION_MISMATCH]      == Severity.CRITICAL

    def test_structural_failures_are_high(self):
        from schemas.integrity import FINDING_SEVERITY
        assert FINDING_SEVERITY[FindingType.SEQUENCE_GAP]          == Severity.HIGH
        assert FINDING_SEVERITY[FindingType.DUPLICATE_SEQUENCE]    == Severity.HIGH
        assert FINDING_SEVERITY[FindingType.TRUNCATED_SESSION]     == Severity.HIGH
        assert FINDING_SEVERITY[FindingType.TOTAL_EVENTS_MISMATCH] == Severity.HIGH
        assert FINDING_SEVERITY[FindingType.MISSING_FIELD]         == Severity.HIGH

    def test_informational_failures_are_medium(self):
        from schemas.integrity import FINDING_SEVERITY
        assert FINDING_SEVERITY[FindingType.MISSING_END_EVENT]  == Severity.MEDIUM
        assert FINDING_SEVERITY[FindingType.TIMESTAMP_ANOMALY]  == Severity.MEDIUM
        assert FINDING_SEVERITY[FindingType.WORKFLOW_ANOMALY]   == Severity.MEDIUM