"""
AFEM Tool: search_email
=======================
Full-text keyword search over emails using SQLite FTS5.

Searches the ``subject``, ``body``, and ``sender`` fields via the
``emails_fts`` virtual table, ordered by BM25 relevance. Falls back to a
SQL ``LIKE`` query if the FTS5 engine rejects the query syntax (e.g. a
bare ``*`` or unmatched parentheses).

Evidence logging is handled by the caller (``agent/langgraph_agent.py``).
"""
from __future__ import annotations

import logging
from typing import List

from db import get_connection
from schemas import SearchResult

logger = logging.getLogger(__name__)

_FTS_SQL = """
SELECT
    e.id,
    e.message_id,
    e.date_raw,
    e.date_ts,
    e.sender,
    e.subject,

    snippet(
        emails_fts,
        1,
        '',
        '',
        '...',
        12
    ) AS snippet

FROM emails_fts
JOIN emails e
ON emails_fts.rowid = e.id

WHERE emails_fts MATCH ?

ORDER BY rank

LIMIT ?
"""

_FALLBACK_SQL = """
    SELECT * FROM emails
    WHERE subject LIKE ? OR body LIKE ? OR sender LIKE ?
    LIMIT ?
"""


def search_email(keyword: str, limit: int = 10) -> List[SearchResult]:
    """
    Search for emails matching a keyword.

    Parameters
    ----------
    keyword : str
        Search term(s). Supports FTS5 query syntax
        (e.g. ``'"payroll update"'`` for phrase search).
    limit : int
        Maximum number of results to return (default ``10``).

    Returns
    -------
    List[SearchResult]
        Matching emails, ordered by FTS5 relevance score (BM25).
        Returns an empty list if no emails match.
    """
    logger.debug("search_email: keyword=%r  limit=%d", keyword, limit)
    results: List[SearchResult] = []

    with get_connection() as conn:
        try:
            rows    = conn.execute(_FTS_SQL, (keyword, limit)).fetchall()
            results = [SearchResult(**dict(r)) for r in rows]
            logger.info(
                "search_email: FTS returned %d results for %r",
                len(results),
                keyword,
            )
        except Exception as exc:
            # FTS5 syntax errors (e.g. bare '*') fall back to LIKE search.
            logger.warning(
                "search_email: FTS failed (%s) — falling back to LIKE",
                exc,
            )
            pattern = f"%{keyword}%"
            rows    = conn.execute(
                _FALLBACK_SQL, (pattern, pattern, pattern, limit)
            ).fetchall()
            results = [SearchResult(**dict(r)) for r in rows]
            logger.info(
                "search_email: LIKE fallback returned %d results",
                len(results),
            )

    return results