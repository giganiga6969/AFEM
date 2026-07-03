"""
AFEM — Mailbox Verification Script
====================================
Runs a battery of SQL queries against mailbox.db and prints a human-readable
health report. Run this after build_mailbox.py to confirm the database is
correctly populated and ready for the LangGraph email agent.

Usage
-----
    # Uses the default path from config.py — no arguments needed:
    python scripts/verify_mailbox.py

    # Override path explicitly:
    python scripts/verify_mailbox.py --db data/processed/mailbox.db
"""

from __future__ import annotations

import argparse
import datetime
import sqlite3
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve project root so this script works from any working directory.
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import MAILBOX_DB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _connect(db_path: Path) -> sqlite3.Connection:
    if not db_path.exists():
        print(f"[ERROR] Database not found: {db_path}")
        print(f"        Have you run scripts/build_mailbox.py yet?")
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _print_header(title: str) -> None:
    bar = "─" * 60
    print(f"\n{bar}")
    print(f"  {title}")
    print(bar)


def _run(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, params).fetchall()


# ---------------------------------------------------------------------------
# Verification checks
# ---------------------------------------------------------------------------

def check_row_count(conn: sqlite3.Connection) -> None:
    _print_header("1. Total Row Count")
    rows = _run(conn, "SELECT COUNT(*) AS total FROM emails")
    print(f"  emails table rows : {rows[0]['total']}")


def check_parse_status_distribution(conn: sqlite3.Connection) -> None:
    _print_header("2. Parse Status Distribution")
    rows = _run(conn, """
        SELECT parse_status, COUNT(*) AS cnt
        FROM emails
        GROUP BY parse_status
        ORDER BY cnt DESC
    """)
    for r in rows:
        print(f"  {r['parse_status']:<12} : {r['cnt']}")


def check_null_fields(conn: sqlite3.Connection) -> None:
    _print_header("3. NULL Field Counts (data completeness)")
    fields = ["date_raw", "date_ts", "recipients", "subject", "body", "cc"]
    for f in fields:
        rows = _run(conn, f"SELECT COUNT(*) AS n FROM emails WHERE {f} IS NULL")
        print(f"  {f:<15} NULL: {rows[0]['n']}")


def check_top_senders(conn: sqlite3.Connection, n: int = 10) -> None:
    _print_header(f"4. Top {n} Senders")
    rows = _run(conn, """
        SELECT sender, COUNT(*) AS cnt
        FROM emails
        GROUP BY sender
        ORDER BY cnt DESC
        LIMIT ?
    """, (n,))
    for r in rows:
        print(f"  {r['cnt']:>4}  {r['sender']}")


def check_date_range(conn: sqlite3.Connection) -> None:
    _print_header("5. Date Range (parsed timestamps)")
    rows = _run(conn, """
        SELECT
            MIN(date_ts) AS earliest,
            MAX(date_ts) AS latest
        FROM emails
        WHERE date_ts IS NOT NULL
    """)
    r = rows[0]
    if r["earliest"]:
        earliest = datetime.datetime.fromtimestamp(
            r["earliest"], tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d")
        latest = datetime.datetime.fromtimestamp(
            r["latest"], tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d")
        print(f"  Earliest : {earliest}")
        print(f"  Latest   : {latest}")
    else:
        print("  No parsed timestamps available.")


def check_duplicate_message_ids(conn: sqlite3.Connection) -> None:
    _print_header("6. Duplicate Message-IDs")
    rows = _run(conn, """
        SELECT COUNT(*) AS dupes
        FROM (
            SELECT message_id
            FROM emails
            GROUP BY message_id
            HAVING COUNT(*) > 1
        )
    """)
    dupes  = rows[0]["dupes"]
    status = "PASS ✓" if dupes == 0 else f"WARN — {dupes} duplicates found"
    print(f"  {status}")


def check_content_hash_uniqueness(conn: sqlite3.Connection) -> None:
    _print_header("7. Content Hash Uniqueness (integrity check)")
    rows = _run(conn, """
        SELECT COUNT(*) AS total, COUNT(DISTINCT content_hash) AS unique_hashes
        FROM emails
    """)
    r          = rows[0]
    collisions = r["total"] - r["unique_hashes"]
    status     = "PASS ✓" if collisions == 0 else f"WARN — {collisions} hash collision(s)"
    print(f"  Total rows       : {r['total']}")
    print(f"  Unique hashes    : {r['unique_hashes']}")
    print(f"  Hash collisions  : {collisions}  →  {status}")


def check_fts_works(conn: sqlite3.Connection) -> None:
    _print_header("8. FTS5 Search Test  (subject MATCH 'meeting')")
    rows = _run(conn, """
        SELECT e.id, e.sender, e.subject
        FROM emails_fts
        JOIN emails e ON emails_fts.rowid = e.id
        WHERE emails_fts MATCH 'meeting'
        LIMIT 5
    """)
    if rows:
        for r in rows:
            subj = (r["subject"] or "")[:60]
            print(f"  [{r['id']:>3}] {r['sender'][:30]:<30}  {subj}")
    else:
        print("  No matches — try a different keyword.")


def check_sample_rows(conn: sqlite3.Connection, n: int = 3) -> None:
    _print_header(f"9. Sample Rows (first {n})")
    rows = _run(conn, """
        SELECT id, message_id, sender, subject, date_raw, parse_status,
               LENGTH(body) AS body_len
        FROM emails
        WHERE parse_status IN ('ok', 'partial')
        ORDER BY id
        LIMIT ?
    """, (n,))
    for r in rows:
        print(f"\n  id           : {r['id']}")
        print(f"  message_id   : {(r['message_id'] or '')[:70]}")
        print(f"  sender       : {r['sender']}")
        print(f"  subject      : {(r['subject'] or '')[:60]}")
        print(f"  date_raw     : {r['date_raw']}")
        print(f"  parse_status : {r['parse_status']}")
        print(f"  body_len     : {r['body_len']} chars")


def check_indexes(conn: sqlite3.Connection) -> None:
    _print_header("10. Index Inventory")
    rows = _run(conn, """
        SELECT name, tbl_name
        FROM sqlite_master
        WHERE type = 'index'
        ORDER BY tbl_name, name
    """)
    for r in rows:
        print(f"  {r['tbl_name']:<20} → {r['name']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def verify(db_path: Path) -> None:
    print(f"\n{'═' * 60}")
    print(f"  AFEM Mailbox Verification Report")
    print(f"  Database: {db_path.resolve()}")
    print(f"{'═' * 60}")

    conn = _connect(db_path)
    try:
        check_row_count(conn)
        check_parse_status_distribution(conn)
        check_null_fields(conn)
        check_top_senders(conn)
        check_date_range(conn)
        check_duplicate_message_ids(conn)
        check_content_hash_uniqueness(conn)
        check_fts_works(conn)
        check_sample_rows(conn)
        check_indexes(conn)
    finally:
        conn.close()

    print(f"\n{'═' * 60}")
    print("  Verification complete.")
    print(f"{'═' * 60}\n")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="AFEM — Verify mailbox.db integrity.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--db", type=Path,
        default=MAILBOX_DB,
        help="Path to the mailbox SQLite database",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    verify(args.db)