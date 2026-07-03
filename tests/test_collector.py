"""
Tests for AFEM EvidenceCollector.

Validates:
- Every event type is written correctly to JSONL.
- ``sequence_number`` is assigned monotonically within a session.
- ``total_events`` in ``SessionEndEvent`` reflects events before the end.
- Invalid tool names are rejected at the collector boundary.
- Multiple sessions in one file remain correctly separated.

Run:
    python -m pytest tests/test_collector.py -v
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest

from collector import EvidenceCollector
from schemas import EventType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_evidence(tmp_path: Path) -> Path:
    return tmp_path / "test_evidence.jsonl"


@pytest.fixture
def collector(tmp_evidence: Path) -> EvidenceCollector:
    return EvidenceCollector(session_id=str(uuid.uuid4()), output_path=tmp_evidence)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _read_events(path: Path) -> list[dict]:
    """Return all JSONL events from the given file as parsed dicts."""
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


# ---------------------------------------------------------------------------
# Basic write tests
# ---------------------------------------------------------------------------

class TestEvidenceCollector:
    def test_file_created_on_first_write(self, collector, tmp_evidence):
        collector.log_user_prompt(content="hello")
        assert tmp_evidence.exists()

    def test_session_start_written(self, collector, tmp_evidence):
        collector.log_session_start(user_prompt="test prompt", model="claude-test")
        events = _read_events(tmp_evidence)
        assert len(events) == 1
        assert events[0]["event_type"] == EventType.SESSION_START

    def test_user_prompt_written(self, collector, tmp_evidence):
        collector.log_user_prompt(content="find payroll emails")
        events = _read_events(tmp_evidence)
        assert events[0]["event_type"] == EventType.USER_PROMPT
        assert events[0]["content"]    == "find payroll emails"

    def test_tool_call_written(self, collector, tmp_evidence):
        collector.log_tool_call(tool_name="search_email", input_data={"keyword": "payroll"})
        events = _read_events(tmp_evidence)
        e = events[0]
        assert e["event_type"]            == EventType.TOOL_CALL
        assert e["tool_name"]             == "search_email"
        assert e["input_data"]["keyword"] == "payroll"

    def test_tool_result_written(self, collector, tmp_evidence):
        collector.log_tool_result(
            tool_name="search_email",
            output_data=[{"id": 1, "subject": "Payroll"}],
            row_count=1,
        )
        events = _read_events(tmp_evidence)
        e = events[0]
        assert e["event_type"]                == EventType.TOOL_RESULT
        assert e["row_count"]                 == 1
        assert e["output_data"][0]["subject"] == "Payroll"

    def test_agent_response_written(self, collector, tmp_evidence):
        collector.log_agent_response(content="Here are the payroll emails.")
        events = _read_events(tmp_evidence)
        assert events[0]["event_type"] == EventType.AGENT_RESPONSE
        assert "payroll" in events[0]["content"].lower()

    def test_session_end_total_events_excludes_self(self, collector, tmp_evidence):
        """total_events must be the count BEFORE the session_end event."""
        collector.log_user_prompt("x")      # event 0
        collector.log_agent_response("y")   # event 1
        collector.log_session_end()         # event 2 — total_events should be 2

        events = _read_events(tmp_evidence)
        end    = next(e for e in events if e["event_type"] == EventType.SESSION_END)
        assert end["total_events"] == 2

    def test_full_session_order(self, collector, tmp_evidence):
        collector.log_session_start(user_prompt="payroll", model="test")
        collector.log_user_prompt(content="payroll")
        collector.log_tool_call(tool_name="search_email", input_data={"keyword": "payroll"})
        collector.log_tool_result(tool_name="search_email", output_data=[], row_count=0)
        collector.log_agent_response(content="No results.")
        collector.log_session_end()

        types = [e["event_type"] for e in _read_events(tmp_evidence)]
        assert types == [
            EventType.SESSION_START,
            EventType.USER_PROMPT,
            EventType.TOOL_CALL,
            EventType.TOOL_RESULT,
            EventType.AGENT_RESPONSE,
            EventType.SESSION_END,
        ]

    def test_session_id_consistent(self, collector, tmp_evidence):
        sid = collector.session_id
        collector.log_user_prompt("x")
        collector.log_agent_response("y")
        for e in _read_events(tmp_evidence):
            assert e["session_id"] == sid

    def test_error_logged_in_tool_result(self, collector, tmp_evidence):
        collector.log_tool_result(
            tool_name="send_email",
            output_data=None,
            error="No draft with id=999",
        )
        events = _read_events(tmp_evidence)
        assert events[0]["error"]       == "No draft with id=999"
        assert events[0]["output_data"] is None

    def test_each_line_is_valid_json(self, collector, tmp_evidence):
        collector.log_session_start(user_prompt="x", model="y")
        collector.log_user_prompt("x")
        collector.log_session_end()
        with open(tmp_evidence, encoding="utf-8") as fh:
            for line in fh:
                json.loads(line)  # must not raise


# ---------------------------------------------------------------------------
# Sequence number tests
# ---------------------------------------------------------------------------

class TestSequenceNumbers:
    def test_sequence_numbers_are_monotonic(self, collector, tmp_evidence):
        collector.log_session_start(user_prompt="x", model="y")
        collector.log_user_prompt("x")
        collector.log_tool_call("search_email", {"keyword": "x"})
        collector.log_tool_result("search_email", output_data=[], row_count=0)
        collector.log_agent_response("done")
        collector.log_session_end()

        events = _read_events(tmp_evidence)
        seqs   = [e["sequence_number"] for e in events]
        assert seqs == list(range(len(events))), f"Sequence numbers not contiguous: {seqs}"

    def test_sequence_starts_at_zero(self, collector, tmp_evidence):
        collector.log_user_prompt("first")
        events = _read_events(tmp_evidence)
        assert events[0]["sequence_number"] == 0

    def test_two_sessions_have_independent_sequences(self, tmp_evidence):
        """Each session starts its own sequence from 0."""
        sid_a = str(uuid.uuid4())
        sid_b = str(uuid.uuid4())
        c_a   = EvidenceCollector(session_id=sid_a, output_path=tmp_evidence)
        c_b   = EvidenceCollector(session_id=sid_b, output_path=tmp_evidence)

        c_a.log_user_prompt("session A event 0")
        c_a.log_user_prompt("session A event 1")
        c_b.log_user_prompt("session B event 0")

        events  = _read_events(tmp_evidence)
        a_seqs  = [e["sequence_number"] for e in events if e["session_id"] == sid_a]
        b_seqs  = [e["sequence_number"] for e in events if e["session_id"] == sid_b]

        assert a_seqs == [0, 1]
        assert b_seqs == [0]


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------

class TestCollectorValidation:
    def test_invalid_tool_name_raises(self, collector):
        """The collector must reject unregistered tool names at the boundary."""
        with pytest.raises(ValueError):
            collector.log_tool_call(
                tool_name="nonexistent_tool",
                input_data={},
            )

    def test_all_valid_tool_names_accepted(self, collector, tmp_evidence):
        valid_tools = ["search_email", "retrieve_email", "create_draft", "send_email"]
        for tool in valid_tools:
            collector.log_tool_call(tool_name=tool, input_data={})
        events = _read_events(tmp_evidence)
        assert len(events) == 4