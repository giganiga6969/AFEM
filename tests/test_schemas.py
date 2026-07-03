"""
Tests for AFEM Pydantic schemas.

Validates that:
- Every event type serialises and deserialises correctly.
- ``ToolName`` coercion works for valid values and rejects invalid ones.
- ``EmailRecord`` and ``DraftRecord`` are importable from ``schemas`` (not
  ``schemas.evidence``), confirming the module split is correct.
- ``sequence_number`` is present in serialised events.

Run:
    python -m pytest tests/test_schemas.py -v
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

from schemas import (
    AgentResponseEvent,
    DraftRecord,
    EmailRecord,
    EventType,
    SessionEndEvent,
    SessionStartEvent,
    ToolCallEvent,
    ToolName,
    ToolResultEvent,
    UserPromptEvent,
)

SESSION_ID = str(uuid.uuid4())


class TestEventSerialization:
    """Every event type must round-trip through to_jsonl() / json.loads()."""

    def _roundtrip(self, event) -> dict:
        return json.loads(event.to_jsonl())

    def test_session_start(self):
        e = SessionStartEvent(session_id=SESSION_ID, user_prompt="test", model="claude-x")
        d = self._roundtrip(e)
        assert d["event_type"]     == EventType.SESSION_START
        assert d["user_prompt"]    == "test"
        assert "timestamp"         in d
        assert "sequence_number"   in d

    def test_user_prompt(self):
        e = UserPromptEvent(session_id=SESSION_ID, content="find payroll")
        d = self._roundtrip(e)
        assert d["event_type"] == EventType.USER_PROMPT
        assert d["content"]    == "find payroll"

    def test_tool_call_with_enum_name(self):
        e = ToolCallEvent(
            session_id=SESSION_ID,
            tool_name=ToolName.SEARCH_EMAIL,
            input_data={"keyword": "payroll", "limit": 5},
        )
        d = self._roundtrip(e)
        assert d["event_type"]            == EventType.TOOL_CALL
        assert d["tool_name"]             == "search_email"   # serialised as string
        assert d["input_data"]["keyword"] == "payroll"

    def test_tool_call_with_string_name(self):
        # ToolName coercion: passing the string value should also work.
        e = ToolCallEvent(
            session_id=SESSION_ID,
            tool_name="retrieve_email",
            input_data={"identifier": "42"},
        )
        d = self._roundtrip(e)
        assert d["tool_name"] == "retrieve_email"

    def test_tool_call_invalid_name_raises(self):
        with pytest.raises(Exception):  # pydantic ValidationError
            ToolCallEvent(
                session_id=SESSION_ID,
                tool_name="nonexistent_tool",
                input_data={},
            )

    def test_tool_result_with_data(self):
        e = ToolResultEvent(
            session_id=SESSION_ID,
            tool_name=ToolName.SEARCH_EMAIL,
            output_data=[{"id": 1}],
            row_count=1,
        )
        d = self._roundtrip(e)
        assert d["event_type"] == EventType.TOOL_RESULT
        assert d["row_count"]  == 1
        assert d["error"]      is None

    def test_tool_result_with_error(self):
        e = ToolResultEvent(
            session_id=SESSION_ID,
            tool_name=ToolName.SEND_EMAIL,
            output_data=None,
            error="Draft not found",
        )
        d = self._roundtrip(e)
        assert d["error"]       == "Draft not found"
        assert d["output_data"] is None

    def test_agent_response(self):
        e = AgentResponseEvent(session_id=SESSION_ID, content="Here are the results.")
        d = self._roundtrip(e)
        assert d["event_type"] == EventType.AGENT_RESPONSE

    def test_session_end(self):
        e = SessionEndEvent(session_id=SESSION_ID, total_events=5)
        d = self._roundtrip(e)
        assert d["event_type"]   == EventType.SESSION_END
        assert d["total_events"] == 5
        assert d["status"]       == "completed"

    def test_session_end_error_status(self):
        e = SessionEndEvent(session_id=SESSION_ID, total_events=2, status="error")
        d = self._roundtrip(e)
        assert d["status"] == "error"


class TestEmailRecordAndDraftRecord:
    """
    Confirm mailbox models are importable from ``schemas`` and that
    they live in ``schemas.email`` (not ``schemas.evidence``).
    """

    def test_email_record_importable_from_schemas(self):
        from schemas import EmailRecord as ER  # noqa: F401

    def test_draft_record_importable_from_schemas(self):
        from schemas import DraftRecord as DR  # noqa: F401

    def test_email_record_source_module(self):
        import schemas.email as email_mod
        assert EmailRecord.__module__ == email_mod.__name__

    def test_minimal_email_record(self):
        r = EmailRecord(
            id=1,
            sender="hr@enron.com",
            content_hash="abc123",
            ingested_at=1234567890,
            parse_status="ok",
        )
        assert r.id      == 1
        assert r.subject is None
        assert r.body    is None

    def test_full_email_record_serialises(self):
        r = EmailRecord(
            id=5,
            message_id="<test@enron.com>",
            date_raw="Mon, 14 May 2001",
            date_ts=989827200,
            sender="hr@enron.com",
            recipients="all@enron.com",
            cc=None,
            subject="Payroll update",
            body="See attached.",
            content_hash="deadbeef",
            ingested_at=1234567890,
            source_file="enron/hr/1",
            parse_status="ok",
        )
        d = r.model_dump()
        assert d["subject"]      == "Payroll update"
        assert d["parse_status"] == "ok"

    def test_draft_record(self):
        d = DraftRecord(
            id=99,
            message_id="<draft-abc@afem.local>",
            sender="agent@afem.local",
            recipients="user@enron.com",
            subject="Test",
            body="Body text.",
            parse_status="draft",
        )
        assert d.parse_status == "draft"