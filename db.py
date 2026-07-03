from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from config import MAILBOX_DB


@contextmanager
def get_connection(db_path: Path = MAILBOX_DB) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager that yields an open, row-factory-enabled SQLite connection.

    Commits on clean exit; rolls back and re-raises on any exception.

    Parameters
    ----------
    db_path :
        Path to the SQLite database file. Defaults to ``config.MAILBOX_DB``
        (``data/processed/mailbox.db``). Override in tests to use a temporary
        database without affecting production data.

    Yields
    ------
    sqlite3.Connection
        A configured connection with row_factory set to ``sqlite3.Row``.

    Example
    -------
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM emails WHERE id = ?", (42,)
            ).fetchone()
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()