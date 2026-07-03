"""
AFEM Tool: create_draft
=======================
Creates a draft email in mailbox.db with ``parse_status='draft'``.

Drafts are stored in the same ``emails`` table as ingested Enron messages,
distinguished only by ``parse_status``. This lets forensic queries find
agent-created drafts alongside received mail in a single table scan, and
makes the database schema simpler (no separate drafts table).

Evidence logging is handled by the caller (``agent/langgraph_agent.py``).
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from typing import Optional

from db import get_connection
from schemas import DraftRecord

logger = logging.getLogger(__name__)

_INSERT_SQL = """
INSERT INTO emails
  (message_id, date_raw, date_ts, sender, recipients, cc,
   subject, body, content_hash, ingested_at, source_file, parse_status)
VALUES
  (:message_id, :date_raw, :date_ts, :sender, :recipients, :cc,
   :subject, :body, :content_hash, :ingested_at, :source_file, :parse_status)
"""


def create_draft(
    sender:     str,
    recipients: str,
    subject:    str,
    body:       str,
    cc:         Optional[str] = None,
) -> DraftRecord:
    """
    Create a new draft email and persist it to mailbox.db.

    Parameters
    ----------
    sender :
        From address (e.g. ``'agent@afem.local'``).
    recipients :
        To addresses, comma-separated (e.g. ``'hr@enron.com'``).
    subject :
        Email subject line.
    body :
        Plain-text email body.
    cc :
        Cc addresses, comma-separated. Optional.

    Returns
    -------
    DraftRecord
        The newly created draft, including its assigned database row id.
    """
    now          = int(time.time())
    msg_id       = f"<draft-{uuid.uuid4().hex[:12]}@afem.local>"
    date_raw     = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(now))
    content_hash = hashlib.sha256(
        f"{msg_id}|{sender}|{subject}|{body}".encode()
    ).hexdigest()

    params = {
        "message_id":   msg_id,
        "date_raw":     date_raw,
        "date_ts":      now,
        "sender":       sender,
        "recipients":   recipients,
        "cc":           cc,
        "subject":      subject,
        "body":         body,
        "content_hash": content_hash,
        "ingested_at":  now,
        "source_file":  "agent:create_draft",
        "parse_status": "draft",
    }

    with get_connection() as conn:
        cursor = conn.execute(_INSERT_SQL, params)
        row_id = cursor.lastrowid

    record = DraftRecord(
        id=row_id,
        message_id=msg_id,
        sender=sender,
        recipients=recipients,
        subject=subject,
        body=body,
        parse_status="draft",
    )
    logger.info("create_draft: id=%d  message_id=%s", row_id, msg_id)
    return record