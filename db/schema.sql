-- =============================================================================
-- AFEM Mailbox Schema  —  mailbox.db
-- =============================================================================
-- Purpose : Stores parsed Enron email records for use by the LangGraph email
--           agent and the AFEM forensic evidence collection pipeline.
-- Engine  : SQLite 3 with WAL journal mode
-- =============================================================================

PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Core emails table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS emails (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- ── RFC 822 header fields ─────────────────────────────────────────────
    message_id      TEXT UNIQUE,
    -- The Message-ID header serves as the natural key.
    -- Synthetic IDs (<synthetic-*@afem.local>) are generated for emails
    -- that lack this header.

    date_raw        TEXT,
    -- Original Date string exactly as it appears in the header.
    -- Preserved verbatim for forensic chain-of-custody purposes.

    date_ts         INTEGER,
    -- Unix timestamp (UTC) derived from date_raw via parsedate_to_datetime().
    -- NULL when date_raw is absent or malformed.
    -- Indexed for chronological queries and incident timeline reconstruction.

    sender          TEXT NOT NULL,
    -- From header.  Defaults to 'unknown' when absent.

    recipients      TEXT,
    -- To header, raw comma-separated string.
    -- Kept raw to preserve original addressing exactly.

    cc              TEXT,
    -- Cc header, raw comma-separated string.

    subject         TEXT,
    -- Subject header.

    body            TEXT,
    -- Decoded plain-text body (first text/plain MIME part).

    -- ── AFEM forensic fields ──────────────────────────────────────────────
    content_hash    TEXT NOT NULL,
    -- SHA-256(message_id || sender || subject || body).
    -- Lightweight integrity token: allows future agents to detect tampering
    -- or accidental mutation of email content in the database.

    ingested_at     INTEGER NOT NULL,
    -- Unix timestamp (UTC) of when this row was inserted.
    -- Establishes the forensic ingestion timeline.

    source_file     TEXT,
    -- The 'file' column value from the Enron CSV.
    -- Provides provenance back to the original dataset path.

    parse_status    TEXT NOT NULL
    -- 'ok'      → all key fields present and parseable
    -- 'partial' → one or more fields missing/unparseable (still usable)
);

-- ---------------------------------------------------------------------------
-- Indexes  (support agent retrieve/search tools and forensic queries)
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_emails_sender      ON emails (sender);
CREATE INDEX IF NOT EXISTS idx_emails_date_ts     ON emails (date_ts);
CREATE INDEX IF NOT EXISTS idx_emails_subject     ON emails (subject);
CREATE INDEX IF NOT EXISTS idx_emails_ingested_at ON emails (ingested_at);

-- ---------------------------------------------------------------------------
-- FTS5 virtual table  (powers search_email() agent tool)
-- ---------------------------------------------------------------------------
-- Mirrors subject, body, and sender from the emails table.
-- Uses content= to avoid duplicating data on disk.
CREATE VIRTUAL TABLE IF NOT EXISTS emails_fts USING fts5(
    subject,
    body,
    sender,
    content  = 'emails',
    content_rowid = 'id'
);

-- Trigger: keep FTS index in sync on every INSERT
CREATE TRIGGER IF NOT EXISTS emails_ai AFTER INSERT ON emails BEGIN
    INSERT INTO emails_fts (rowid, subject, body, sender)
    VALUES (new.id, new.subject, new.body, new.sender);
END;

-- =============================================================================
-- Agent Tool → Column Mapping  (reference for future LangGraph integration)
-- =============================================================================
--
--  retrieve_email(id)          → SELECT * FROM emails WHERE id = ?
--  retrieve_email(message_id)  → SELECT * FROM emails WHERE message_id = ?
--
--  search_email(keyword)       → SELECT e.* FROM emails_fts
--                                 JOIN emails e ON emails_fts.rowid = e.id
--                                WHERE emails_fts MATCH ?
--
--  create_draft(...)           → INSERT INTO emails (..., parse_status='draft')
--
--  send_email(id)              → UPDATE emails SET parse_status='sent' WHERE id=?
--
--  forensic_collect(id)        → SELECT * FROM emails WHERE id=?
--                                (hash verified against content_hash)
--
-- =============================================================================