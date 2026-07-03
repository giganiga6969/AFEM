"""
AFEM — Mailbox Extraction Pipeline
===================================
Reads the Enron Email Dataset CSV in chunks, parses RFC 822 email messages,
and persists the first MAX_EMAILS valid records into a SQLite mailbox database.

Usage
-----
    # Uses defaults from config.py — no arguments needed after initial setup:
    python scripts/build_mailbox.py

    # Override paths explicitly:
    python scripts/build_mailbox.py --csv data/raw/emails.csv --db data/processed/mailbox.db

The script is intentionally self-contained: only stdlib + pandas are required.
"""

from __future__ import annotations

import argparse
import email
import hashlib
import logging
import sqlite3
import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterator, Optional

import pandas as pd

# ---------------------------------------------------------------------------
# Resolve project root so this script works from any working directory.
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import LOG_DIR, MAILBOX_DB, RAW_DIR

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_EMAILS: int = 1000     # MVP cap — first 1000 valid emails
CHUNK_SIZE: int = 2_000    # Rows read from CSV per iteration
LOG_EVERY:  int = 50       # Log progress every N inserted emails


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _configure_logging(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"build_mailbox_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_path, encoding="utf-8"),
        ],
    )
    logger = logging.getLogger("afem.mailbox")
    logger.info("Log file: %s", log_path)
    return logger


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS emails (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- RFC 822 header fields
    message_id      TEXT UNIQUE,          -- Message-ID header (natural key)
    date_raw        TEXT,                 -- Original Date string from header
    date_ts         INTEGER,              -- Unix timestamp (UTC); NULL if unparseable
    sender          TEXT NOT NULL,        -- From header
    recipients      TEXT,                 -- To header (raw, comma-separated)
    cc              TEXT,                 -- Cc header (raw)
    subject         TEXT,                 -- Subject header
    body            TEXT,                 -- Plain-text body

    -- AFEM forensic fields
    content_hash    TEXT NOT NULL,        -- SHA-256 of (message_id + sender + subject + body)
    ingested_at     INTEGER NOT NULL,     -- Unix timestamp when row was inserted
    source_file     TEXT,                 -- Original CSV 'file' column value

    -- Status / quality flag
    parse_status    TEXT NOT NULL         -- 'ok' | 'partial'
);

-- Search indexes
CREATE INDEX IF NOT EXISTS idx_emails_sender      ON emails (sender);
CREATE INDEX IF NOT EXISTS idx_emails_date_ts     ON emails (date_ts);
CREATE INDEX IF NOT EXISTS idx_emails_subject     ON emails (subject);
CREATE INDEX IF NOT EXISTS idx_emails_ingested_at ON emails (ingested_at);

-- Full-text search virtual table (for search_email() agent tool)
CREATE VIRTUAL TABLE IF NOT EXISTS emails_fts USING fts5(
    subject,
    body,
    sender,
    content='emails',
    content_rowid='id'
);

-- Keep FTS in sync with the main table
CREATE TRIGGER IF NOT EXISTS emails_ai AFTER INSERT ON emails BEGIN
    INSERT INTO emails_fts (rowid, subject, body, sender)
    VALUES (new.id, new.subject, new.body, new.sender);
END;
"""


def _open_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _sha256_content(message_id: str, sender: str, subject: str, body: str) -> str:
    """Deterministic content hash used as a lightweight integrity token."""
    raw = f"{message_id}|{sender}|{subject}|{body}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _parse_date(date_str: Optional[str]) -> Optional[int]:
    """Convert an RFC 2822 date string to a UTC Unix timestamp. Returns None on failure."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        return int(dt.astimezone(timezone.utc).timestamp())
    except Exception:
        return None


def _extract_body(msg: email.message.Message) -> str:
    """
    Walk the MIME tree and return the first text/plain part.
    Falls back to the decoded payload if the message is not multipart.
    """
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="replace").strip()
        return ""
    payload = msg.get_payload(decode=True)
    if payload:
        return payload.decode("utf-8", errors="replace").strip()
    # Non-encoded payload (string already)
    raw = msg.get_payload()
    return raw.strip() if isinstance(raw, str) else ""


def _parse_message(raw_message: str, source_file: str) -> Optional[dict]:
    """
    Parse a single RFC 822 message string.

    Returns a dict ready for DB insertion, or None if the email is unusable
    (e.g. missing both From and body, making it worthless for forensics).
    """
    try:
        msg = email.message_from_string(raw_message)
    except Exception:
        return None

    sender   = (msg.get("From")       or "").strip()
    subject  = (msg.get("Subject")    or "").strip()
    date_raw = (msg.get("Date")       or "").strip()
    to_raw   = (msg.get("To")         or "").strip()
    cc_raw   = (msg.get("Cc")         or "").strip()
    msg_id   = (msg.get("Message-ID") or "").strip()

    body = _extract_body(msg)

    # Discard emails with no identifiable sender and empty body.
    if not sender and not body:
        return None

    # Synthesise a fallback message-id if the header is absent.
    if not msg_id:
        digest = hashlib.md5(raw_message[:512].encode("utf-8", errors="replace")).hexdigest()
        msg_id = f"<synthetic-{digest}@afem.local>"

    parse_status = "ok" if (sender and date_raw and body) else "partial"

    return {
        "message_id":   msg_id,
        "date_raw":     date_raw or None,
        "date_ts":      _parse_date(date_raw),
        "sender":       sender or "unknown",
        "recipients":   to_raw  or None,
        "cc":           cc_raw  or None,
        "subject":      subject or None,
        "body":         body    or None,
        "content_hash": _sha256_content(msg_id, sender, subject, body),
        "ingested_at":  int(time.time()),
        "source_file":  source_file or None,
        "parse_status": parse_status,
    }


# ---------------------------------------------------------------------------
# CSV streaming
# ---------------------------------------------------------------------------

def _iter_csv_chunks(csv_path: Path, chunk_size: int) -> Iterator[pd.DataFrame]:
    """Yield DataFrame chunks from the CSV without loading the entire file."""
    reader = pd.read_csv(
        csv_path,
        chunksize=chunk_size,
        dtype=str,           # treat everything as string; no type coercion
        on_bad_lines="skip", # skip malformed CSV rows silently
        encoding="utf-8",
        encoding_errors="replace",
        low_memory=False,
    )
    yield from reader


# ---------------------------------------------------------------------------
# Insertion
# ---------------------------------------------------------------------------

INSERT_SQL = """
INSERT OR IGNORE INTO emails
    (message_id, date_raw, date_ts, sender, recipients, cc,
     subject, body, content_hash, ingested_at, source_file, parse_status)
VALUES
    (:message_id, :date_raw, :date_ts, :sender, :recipients, :cc,
     :subject, :body, :content_hash, :ingested_at, :source_file, :parse_status)
"""


def _insert_email(conn: sqlite3.Connection, record: dict) -> bool:
    """
    Insert one record. Returns True if a new row was inserted,
    False if the message_id already existed (IGNORE clause).
    """
    cursor = conn.execute(INSERT_SQL, record)
    return cursor.rowcount == 1


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def build_mailbox(
    csv_path:   Path,
    db_path:    Path,
    log_dir:    Path,
    max_emails: int = MAX_EMAILS,
    chunk_size: int = CHUNK_SIZE,
) -> None:
    logger = _configure_logging(log_dir)
    logger.info("=== AFEM Mailbox Build — START ===")
    logger.info("Source CSV : %s", csv_path)
    logger.info("Target DB  : %s", db_path)
    logger.info("Email cap  : %d", max_emails)

    if not csv_path.exists():
        logger.error("CSV not found: %s", csv_path)
        sys.exit(1)

    conn = _open_db(db_path)
    logger.info("Database opened and schema applied.")

    inserted  = 0
    skipped   = 0
    rows_seen = 0

    try:
        for chunk_idx, chunk in enumerate(_iter_csv_chunks(csv_path, chunk_size)):
            if inserted >= max_emails:
                break

            if "message" not in chunk.columns:
                logger.error("CSV is missing the 'message' column. Check your dataset.")
                sys.exit(1)

            # Normalise column names — dataset may use 'file' or 'File'
            chunk.columns = [c.strip().lower() for c in chunk.columns]
            source_col    = "file" if "file" in chunk.columns else None

            for _, row in chunk.iterrows():
                if inserted >= max_emails:
                    break

                rows_seen  += 1
                raw_msg     = row.get("message", "")
                source_file = str(row[source_col]) if source_col else ""

                if not isinstance(raw_msg, str) or not raw_msg.strip():
                    skipped += 1
                    continue

                record = _parse_message(raw_msg, source_file)
                if record is None:
                    skipped += 1
                    continue

                stored = _insert_email(conn, record)
                if stored:
                    inserted += 1
                    if inserted % LOG_EVERY == 0:
                        logger.info(
                            "  Inserted %4d / %d  (rows examined: %d)",
                            inserted,
                            max_emails,
                            rows_seen,
                        )
                else:
                    skipped += 1  # duplicate message-id

            conn.commit()
            logger.debug("Chunk %d committed.", chunk_idx)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user — committing partial results.")
        conn.commit()

    finally:
        conn.close()

    logger.info("=== AFEM Mailbox Build — COMPLETE ===")
    logger.info("Emails inserted : %d", inserted)
    logger.info("Rows skipped    : %d", skipped)
    logger.info("Total CSV rows  : %d", rows_seen)
    logger.info("Database        : %s", db_path.resolve())


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="AFEM — Build Enron mailbox SQLite database from CSV.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--csv", type=Path,
        default=RAW_DIR / "emails.csv",
        help="Path to the Enron CSV file",
    )
    p.add_argument(
        "--db", type=Path,
        default=MAILBOX_DB,
        help="Output SQLite database path",
    )
    p.add_argument(
        "--log-dir", type=Path,
        default=LOG_DIR,
        help="Directory for log files",
    )
    p.add_argument(
        "--max-emails", type=int,
        default=MAX_EMAILS,
        help=f"Maximum emails to ingest",
    )
    p.add_argument(
        "--chunk-size", type=int,
        default=CHUNK_SIZE,
        help="CSV rows per read chunk",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    build_mailbox(
        csv_path   = args.csv,
        db_path    = args.db,
        log_dir    = args.log_dir,
        max_emails = args.max_emails,
        chunk_size = args.chunk_size,
    )