"""
Tests for AFEM email tools.

Runs against the real mailbox.db — no mocking, no LLM required.
Tests are grouped by tool and ordered from simplest to most complex
so failures are easy to diagnose in CI output.

Prerequisites:
    python scripts/build_mailbox.py must have been run at least once.

Run:
    python -m pytest tests/test_tools.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest

from agent.tools import create_draft, retrieve_email, search_email, send_email
from db import get_connection
from schemas import DraftRecord, EmailRecord


# ---------------------------------------------------------------------------
# retrieve_email
# ---------------------------------------------------------------------------

class TestRetrieveEmail:
    def test_returns_email_record_type(self):
        result = retrieve_email(1)
        assert isinstance(result, EmailRecord)

    def test_correct_id_returned(self):
        result = retrieve_email(1)
        assert result is not None
        assert result.id == 1

    def test_sender_is_nonempty(self):
        result = retrieve_email(1)
        assert result is not None
        assert result.sender != ""

    def test_lookup_by_message_id(self):
        with get_connection() as conn:
            row = conn.execute("SELECT message_id FROM emails LIMIT 1").fetchone()
        if row and row["message_id"]:
            result = retrieve_email(row["message_id"])
            assert result is not None
            assert result.message_id == row["message_id"]

    def test_missing_integer_id_returns_none(self):
        assert retrieve_email(9_999_999) is None

    def test_missing_message_id_returns_none(self):
        assert retrieve_email("<does-not-exist@afem.local>") is None


# ---------------------------------------------------------------------------
# search_email
# ---------------------------------------------------------------------------

class TestSearchEmail:
    def test_returns_list(self):
        assert isinstance(search_email("payroll"), list)

    def test_payroll_finds_results(self):
        results = search_email("payroll")
        assert len(results) > 0
        assert all(isinstance(r, EmailRecord) for r in results)

    def test_results_contain_keyword(self):
        for r in search_email("payroll"):
            text = f"{r.subject or ''} {r.body or ''} {r.sender or ''}".lower()
            assert "payroll" in text, f"keyword absent in email id={r.id}"

    def test_limit_is_respected(self):
        assert len(search_email("payroll", limit=2)) <= 2

    def test_no_match_returns_empty_list(self):
        assert search_email("xyzzy_gibberish_impossible_match") == []

    def test_default_limit_is_ten(self):
        # The mailbox has many emails — default limit must cap at 10.
        results = search_email("enron")
        assert len(results) <= 10


# ---------------------------------------------------------------------------
# create_draft
# ---------------------------------------------------------------------------

class TestCreateDraft:
    def test_returns_draft_record(self):
        record = create_draft(
            sender="agent@afem.local",
            recipients="user@enron.com",
            subject="Test draft",
            body="This is a test draft body.",
        )
        assert isinstance(record, DraftRecord)

    def test_id_is_positive(self):
        record = create_draft(
            sender="agent@afem.local",
            recipients="user@enron.com",
            subject="ID check",
            body="Body.",
        )
        assert record.id > 0

    def test_parse_status_is_draft(self):
        record = create_draft(
            sender="agent@afem.local",
            recipients="user@enron.com",
            subject="Status check",
            body="Body.",
        )
        assert record.parse_status == "draft"

    def test_message_id_is_synthetic(self):
        record = create_draft(
            sender="agent@afem.local",
            recipients="user@enron.com",
            subject="ID format",
            body="Body.",
        )
        assert record.message_id.startswith("<draft-")
        assert record.message_id.endswith("@afem.local>")

    def test_draft_persisted_in_db(self):
        record  = create_draft(
            sender="agent@afem.local",
            recipients="target@enron.com",
            subject="Persisted draft",
            body="Persistence check.",
        )
        fetched = retrieve_email(record.id)
        assert fetched is not None
        assert fetched.parse_status == "draft"
        assert fetched.subject      == "Persisted draft"

    def test_cc_stored_in_db(self):
        record  = create_draft(
            sender="agent@afem.local",
            recipients="a@enron.com",
            subject="CC test",
            body="CC body.",
            cc="b@enron.com",
        )
        fetched = retrieve_email(record.id)
        assert fetched is not None
        assert fetched.cc == "b@enron.com"


# ---------------------------------------------------------------------------
# send_email
# ---------------------------------------------------------------------------

class TestSendEmail:
    def _fresh_draft(self) -> DraftRecord:
        return create_draft(
            sender="agent@afem.local",
            recipients="recv@enron.com",
            subject="Draft for send test",
            body="Send me.",
        )

    def test_returns_draft_record(self):
        result = send_email(self._fresh_draft().id)
        assert isinstance(result, DraftRecord)

    def test_status_changes_to_sent(self):
        result = send_email(self._fresh_draft().id)
        assert result.parse_status == "sent"

    def test_status_persisted_in_db(self):
        draft   = self._fresh_draft()
        send_email(draft.id)
        fetched = retrieve_email(draft.id)
        assert fetched is not None
        assert fetched.parse_status == "sent"

    def test_sending_twice_is_idempotent(self):
        draft = self._fresh_draft()
        send_email(draft.id)
        result = send_email(draft.id)   # second call must not raise
        assert result.parse_status == "sent"

    def test_nonexistent_draft_raises_value_error(self):
        with pytest.raises(ValueError, match="No draft found"):
            send_email(99_999_999)
            