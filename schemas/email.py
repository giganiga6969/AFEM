from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class EmailRecord(BaseModel):
    """
    Represents one row from the ``emails`` table in mailbox.db.

    Returned by ``retrieve_email()`` and ``search_email()``. The agent
    always receives structured data — not raw dicts — so type errors are
    caught at the tool boundary rather than inside the LLM loop.

    ``parse_status`` values
    -----------------------
    - ``'ok'``      : all key fields present and parseable
    - ``'partial'`` : one or more fields missing or unparseable (still usable)
    - ``'draft'``   : agent-created draft awaiting send
    - ``'sent'``    : agent-sent email (status set by ``send_email()``)
    """

    id:           int
    message_id:   Optional[str] = None
    date_raw:     Optional[str] = None
    date_ts:      Optional[int] = None
    sender:       str
    recipients:   Optional[str] = None
    cc:           Optional[str] = None
    subject:      Optional[str] = None
    body:         Optional[str] = None
    content_hash: str
    ingested_at:  int
    source_file:  Optional[str] = None
    parse_status: str           # 'ok' | 'partial' | 'draft' | 'sent'


class DraftRecord(BaseModel):
    """
    Represents a draft or sent email row in mailbox.db.

    Returned by ``create_draft()`` and ``send_email()``. Uses a narrower
    schema than ``EmailRecord`` because agents creating drafts always supply
    all required fields, whereas ingested emails may have missing headers.
    """

    id:           int
    message_id:   str
    sender:       str
    recipients:   str
    subject:      str
    body:         str
    parse_status: str           # 'draft' | 'sent'

class SearchResult(BaseModel):

    id: int

    message_id: Optional[str]=None

    sender: str

    subject: Optional[str]=None

    date_raw: Optional[str]=None

    date_ts: Optional[int]=None

    snippet: Optional[str]=None