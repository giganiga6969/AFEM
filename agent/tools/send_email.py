"""
AFEM Tool: send_email
=====================
"Sends" an email by updating its ``parse_status`` from ``'draft'`` to
``'sent'`` in mailbox.db.

In this research prototype, sending is simulated — no SMTP connection is
made. The forensic significance is that the agent's send action is recorded
both in mailbox.db (the status change) and in evidence.jsonl (a
``ToolCallEvent`` + ``ToolResultEvent`` pair), creating a complete and
verifiable action trail.

Evidence logging is handled by the caller (``agent/langgraph_agent.py``).
"""
from __future__ import annotations

import logging

from db import get_connection
from schemas import DraftRecord

logger = logging.getLogger(__name__)

_FETCH_SQL  = "SELECT * FROM emails WHERE id = ? AND parse_status IN ('draft', 'sent')"
_UPDATE_SQL = "UPDATE emails SET parse_status = 'sent' WHERE id = ? AND parse_status = 'draft'"


def send_email(draft_id: int) -> DraftRecord:
    """
    Mark a draft as sent.

    Calling this on an already-sent email is idempotent: the record is
    returned unchanged rather than raising an error. This mirrors the
    semantics of a real SMTP ``250 OK`` response received a second time
    after a retry.

    Parameters
    ----------
    draft_id : int
        The integer row id of the draft email to send.

    Returns
    -------
    DraftRecord
        The email record with ``parse_status`` set to ``'sent'``.

    Raises
    ------
    ValueError
        If no row with ``id = draft_id`` and a draft/sent status exists.
    """
    logger.debug("send_email: draft_id=%d", draft_id)

    with get_connection() as conn:
        row = conn.execute(_FETCH_SQL, (draft_id,)).fetchone()
        if row is None:
            raise ValueError(f"No draft found with id={draft_id}")

        if row["parse_status"] == "sent":
            logger.info("send_email: id=%d already sent (idempotent)", draft_id)
        else:
            conn.execute(_UPDATE_SQL, (draft_id,))
            logger.info("send_email: id=%d marked as sent", draft_id)

        # Re-fetch to return the authoritative committed state.
        row = conn.execute("SELECT * FROM emails WHERE id = ?", (draft_id,)).fetchone()

    return DraftRecord(
        id=row["id"],
        message_id=row["message_id"],
        sender=row["sender"],
        recipients=row["recipients"],
        subject=row["subject"],
        body=row["body"],
        parse_status=row["parse_status"],
    )