"""
AFEM Tool: retrieve_email
=========================
Fetches a single email from mailbox.db by its integer row id or its
Message-ID header string.

Evidence logging is handled by the caller (``agent/langgraph_agent.py``) via
the ``EvidenceCollector`` passed through agent state — not inside this
function. This keeps the tool pure and independently testable without any
LangGraph or collector dependency.
"""
from __future__ import annotations

import logging
from typing import Optional, Union

from db import get_connection
from schemas import EmailRecord

logger = logging.getLogger(__name__)

_SELECT_BY_ID  = "SELECT * FROM emails WHERE id = ?"
_SELECT_BY_MID = "SELECT * FROM emails WHERE message_id = ?"


def retrieve_email(identifier: Union[int, str]) -> Optional[EmailRecord]:
    """
    Retrieve a single email from mailbox.db.

    Parameters
    ----------
    identifier : int | str
        Integer row id  (e.g. ``42``) for primary-key lookup, or a
        Message-ID string (e.g. ``'<payroll-q2@enron.com>'``) for header
        lookup.

    Returns
    -------
    EmailRecord | None
        Structured email record, or ``None`` if no matching row is found.
    """
    sql   = _SELECT_BY_ID if isinstance(identifier, int) else _SELECT_BY_MID
    param = identifier

    logger.debug("retrieve_email: identifier=%r", identifier)

    with get_connection() as conn:
        row = conn.execute(sql, (param,)).fetchone()

    if row is None:
        logger.info("retrieve_email: no record found for identifier=%r", identifier)
        return None

    record = EmailRecord(**dict(row))
    logger.info("retrieve_email: found id=%d  subject=%r", record.id, record.subject)
    return record