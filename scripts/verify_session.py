#!/usr/bin/env python3
"""
AFEM — Forensic Evidence Integrity Verification
================================================
Investigator-facing command-line tool for verifying the SHA-256 hash chain
integrity of AFEM session evidence files.

This script is a pure presentation layer. All verification logic lives in
``integrity/verifier.py``. This script only formats and displays the report.

Usage
-----
Verify a single session file:
    python scripts/verify_session.py data/evidence/sessions/<uuid>.jsonl

Verify a single session, output full JSON report:
    python scripts/verify_session.py data/evidence/sessions/<uuid>.jsonl --json

List available sessions (no path required):
    python scripts/verify_session.py --list

Verify all sessions in the default evidence directory:
    python scripts/verify_session.py --all

Verify all sessions, continue on errors:
    python scripts/verify_session.py --all --skip-errors

Exit codes
----------
0   All verified sessions have chain_valid=True (VERIFIED or no sessions found)
1   One or more sessions have chain_valid=False (FAILED) or an error occurred
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure AFEM project root is on sys.path so imports resolve from any CWD.
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import EVIDENCE_FILE
from integrity.verifier import verify_session, verify_sessions_dir
from schemas.integrity import (
    EvidenceTrust,
    FindingType,
    ForensicFinding,
    IntegrityReport,
    Severity,
)

# ---------------------------------------------------------------------------
# Default evidence directory
# ---------------------------------------------------------------------------

_DEFAULT_SESSIONS_DIR = EVIDENCE_FILE.parent / "sessions"


# ---------------------------------------------------------------------------
# Formatting constants
# ---------------------------------------------------------------------------

_WIDTH     = 68
_SEPARATOR = "─" * _WIDTH
_DOUBLE    = "═" * _WIDTH

# ANSI colour codes — automatically suppressed on non-TTY output (piped).
_USE_COLOUR = sys.stdout.isatty()


def _colour(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text


def _green(text: str)  -> str: return _colour(text, "32")
def _red(text: str)    -> str: return _colour(text, "31")
def _yellow(text: str) -> str: return _colour(text, "33")
def _cyan(text: str)   -> str: return _colour(text, "36")
def _bold(text: str)   -> str: return _colour(text, "1")
def _dim(text: str)    -> str: return _colour(text, "2")


# ---------------------------------------------------------------------------
# Severity colour mapping
# ---------------------------------------------------------------------------

_SEVERITY_COLOUR = {
    Severity.LOW:      _dim,
    Severity.MEDIUM:   _yellow,
    Severity.HIGH:     _yellow,
    Severity.CRITICAL: _red,
}

_TRUST_COLOUR = {
    EvidenceTrust.TRUSTED:     _green,
    EvidenceTrust.DEGRADED:    _yellow,
    EvidenceTrust.COMPROMISED: _red,
    EvidenceTrust.UNKNOWN:     _red,
}


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _print_report(report: IntegrityReport, path: Path) -> None:
    """Pretty-print a full forensic verification report to stdout."""
    p = print

    # ── Header ──────────────────────────────────────────────────────────
    p(_double_line())
    p(_centre("  AFEM — FORENSIC EVIDENCE INTEGRITY REPORT  "))
    p(_double_line())
    p()

    # ── Session summary ──────────────────────────────────────────────────
    verdict_text = _bold(_green("✓  VERIFIED")) if report.chain_valid \
        else _bold(_red("✗  FAILED"))
    trust_fn     = _TRUST_COLOUR.get(report.evidence_trust, _dim)

    p(_section("SESSION SUMMARY"))
    p(f"  {'File':<22} {path.name}")
    p(f"  {'Session ID':<22} {report.session_id}")
    p(f"  {'Verified At':<22} {report.verified_at}")
    p(f"  {'Integrity Status':<22} {verdict_text}")
    p(f"  {'Evidence Trust':<22} {trust_fn(report.evidence_trust.value.upper())}")
    p(f"  {'Session Complete':<22} {'Yes' if report.session_complete else _yellow('No')}")
    p(f"  {'Total Events':<22} {report.total_events}")
    p()

    # ── Hash anchors ─────────────────────────────────────────────────────
    p(_section("HASH CHAIN ANCHORS"))
    p(f"  {'Genesis Hash':<22} {_dim(report.genesis_hash or 'N/A')}")
    p(f"  {'Terminal Hash':<22} {_dim(report.terminal_hash or 'N/A')}")
    p()

    # ── Findings ─────────────────────────────────────────────────────────
    if report.findings:
        p(_section(f"FINDINGS  ({len(report.findings)} detected)"))
        for i, finding in enumerate(report.findings, start=1):
            colour_fn = _SEVERITY_COLOUR.get(finding.severity, _dim)
            sev_label = colour_fn(f"[{finding.severity.value.upper()}]")
            seq_label = (
                f"seq {finding.affected_sequence}"
                if finding.affected_sequence is not None
                else "session-level"
            )
            p(f"  {i:>2}. {sev_label} {_bold(finding.finding_type.value)}")
            p(f"      Location : {seq_label}")
            p(f"      Detail   : {_wrap(finding.message, indent=15)}")
            p()
    else:
        p(_section("FINDINGS"))
        p(f"  {_green('No findings — evidence integrity confirmed.')}")
        p()

    # ── Workflow anomalies ───────────────────────────────────────────────
    if report.workflow_anomalies:
        p(_section("WORKFLOW ANOMALIES"))
        for anomaly in report.workflow_anomalies:
            p(f"  • {_yellow(anomaly)}")
        p()

    # ── Per-event chain table ────────────────────────────────────────────
    p(_section("EVENT CHAIN VERIFICATION"))
    p(f"  {'Seq':<5} {'Type':<20} {'Status':<12} {'Prev Hash':>15}  {'Event Hash':>15}")
    p(f"  {'─'*4} {'─'*19} {'─'*11} {'─'*15}  {'─'*15}")

    for ev in report.events:
        status = _green("✓ valid") if ev.is_valid else _red("✗ FAILED")
        prev_h = (ev.actual_prev[:12]  + "...") if ev.actual_prev  else "N/A"
        evnt_h = (ev.actual_hash[:12]  + "...") if ev.actual_hash  else "N/A"
        prev_c = _dim(prev_h) if ev.is_valid else _red(prev_h)
        evnt_c = _dim(evnt_h) if ev.is_valid else _red(evnt_h)
        p(f"  {ev.sequence_number:<5} {ev.event_type:<20} {status:<20} {prev_c:>15}  {evnt_c:>15}")

    p()

    # ── Failure detail (only when chain is broken) ────────────────────────
    if not report.chain_valid:
        p(_section("FAILURE DETAIL"))
        p(f"  {'First Broken Event':<22} {report.first_broken_seq}")
        p(f"  {'Failure Type':<22} {_red(str(report.first_failure_type.value if report.first_failure_type else 'unknown'))}")
        p()
        broken = [ev for ev in report.events if not ev.is_valid]
        for ev in broken:
            p(f"  {_red('✗')} Event {ev.sequence_number} ({ev.event_type})")
            if ev.failure_reason:
                p(f"    {_red(ev.failure_reason)}")
        p()

    # ── Footer ───────────────────────────────────────────────────────────
    p(_double_line())
    verdict_line = (
        _green("  INTEGRITY VERIFIED — Evidence chain is intact.")
        if report.chain_valid
        else _red("  INTEGRITY FAILED  — Evidence integrity violation detected.")
    )
    p(verdict_line)
    p(_double_line())
    p()


def _print_summary_table(reports: list[IntegrityReport], sessions_dir: Path) -> None:
    """Print a compact summary table for multiple sessions."""
    p = print
    p(_double_line())
    p(_centre("  AFEM — SESSION INTEGRITY SUMMARY  "))
    p(_double_line())
    p(f"\n  Directory: {sessions_dir}\n")
    p(f"  {'Session ID':<38} {'Trust':<14} {'Status':<10} {'Events':<8} {'Findings'}")
    p(f"  {'─'*37} {'─'*13} {'─'*9} {'─'*7} {'─'*8}")

    for r in reports:
        trust_fn = _TRUST_COLOUR.get(r.evidence_trust, _dim)
        status   = _green("VERIFIED") if r.chain_valid else _red("FAILED  ")
        trust    = trust_fn(r.evidence_trust.value.upper().ljust(10))
        sid      = r.session_id[:36]
        p(f"  {sid:<38} {trust}  {status}  {r.total_events:<8} {len(r.findings)}")

    p()
    verified = sum(1 for r in reports if r.chain_valid)
    failed   = len(reports) - verified
    p(f"  Total: {len(reports)}   {_green(f'Verified: {verified}')}   {_red(f'Failed: {failed}')}")
    p(_double_line())
    p()


# ---------------------------------------------------------------------------
# Session listing
# ---------------------------------------------------------------------------


def _list_sessions(sessions_dir: Path) -> None:
    """Print available session files with basic metadata."""
    p = print
    if not sessions_dir.exists():
        p(f"Sessions directory not found: {sessions_dir}")
        p("Run the LangGraph agent first to generate evidence sessions.")
        return

    files = sorted(sessions_dir.glob("*.jsonl"))
    if not files:
        p(f"No session files found in: {sessions_dir}")
        return

    p(f"\n  {'#':<4} {'Session File':<45} {'Size':>8}")
    p(f"  {'─'*3} {'─'*44} {'─'*8}")
    for i, f in enumerate(files, 1):
        size = f.stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} B"
        p(f"  {i:<4} {f.name:<45} {size_str:>8}")
    p(f"\n  {len(files)} session(s) found.\n")
    p(f"  Verify a session with:")
    p(f"    python scripts/verify_session.py {files[0]}\n")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _section(title: str) -> str:
    return f"  {_bold(title)}\n  {_SEPARATOR}"


def _double_line() -> str:
    return _DOUBLE


def _centre(text: str) -> str:
    return text.center(_WIDTH)


def _wrap(text: str, indent: int = 10, width: int = _WIDTH) -> str:
    """Simple word-wrap for long finding messages."""
    available = width - indent
    if len(text) <= available:
        return text
    words   = text.split()
    lines   = []
    current = []
    length  = 0
    for word in words:
        if length + len(word) + 1 > available and current:
            lines.append(" ".join(current))
            current = [word]
            length  = len(word)
        else:
            current.append(word)
            length += len(word) + 1
    if current:
        lines.append(" ".join(current))
    pad = " " * indent
    return ("\n" + pad).join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AFEM — Forensic evidence integrity verification tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/verify_session.py data/evidence/sessions/abc-123.jsonl
  python scripts/verify_session.py data/evidence/sessions/abc-123.jsonl --json
  python scripts/verify_session.py --list
  python scripts/verify_session.py --all
  python scripts/verify_session.py --all --skip-errors
        """,
    )
    parser.add_argument(
        "session_file",
        nargs="?",
        type=Path,
        default=None,
        help="Path to a specific session .jsonl file to verify.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available session files in the evidence directory.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Verify all session files in the evidence directory.",
    )
    parser.add_argument(
        "--sessions-dir",
        type=Path,
        default=_DEFAULT_SESSIONS_DIR,
        help=f"Evidence sessions directory (default: {_DEFAULT_SESSIONS_DIR}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the full IntegrityReport as JSON (single session only).",
    )
    parser.add_argument(
        "--skip-errors",
        action="store_true",
        help="With --all: continue past sessions that raise errors.",
    )

    args = parser.parse_args()

    # ── --list ───────────────────────────────────────────────────────────
    if args.list:
        _list_sessions(args.sessions_dir)
        return 0

    # ── --all ────────────────────────────────────────────────────────────
    if args.all:
        if not args.sessions_dir.exists():
            print(f"Sessions directory not found: {args.sessions_dir}", file=sys.stderr)
            return 1
        try:
            reports = verify_sessions_dir(
                args.sessions_dir,
                skip_errors=args.skip_errors,
            )
        except Exception as exc:
            print(f"Error verifying sessions: {exc}", file=sys.stderr)
            return 1

        if not reports:
            print(f"No session files found in: {args.sessions_dir}")
            return 0

        _print_summary_table(reports, args.sessions_dir)
        failed = [r for r in reports if not r.chain_valid]
        return 1 if failed else 0

    # ── single session ───────────────────────────────────────────────────
    if args.session_file is None:
        # No path given and no --list/--all: try to be helpful.
        if _DEFAULT_SESSIONS_DIR.exists():
            files = sorted(_DEFAULT_SESSIONS_DIR.glob("*.jsonl"))
            if files:
                print("No session file specified. Available sessions:")
                _list_sessions(_DEFAULT_SESSIONS_DIR)
                print("Usage: python scripts/verify_session.py <session_file>")
                return 1
        print("No session file specified. Use --list to see available sessions.")
        print("Usage: python scripts/verify_session.py <session_file>")
        return 1

    if not args.session_file.exists():
        print(f"Session file not found: {args.session_file}", file=sys.stderr)
        return 1

    try:
        report = verify_session(args.session_file)
    except Exception as exc:
        print(f"Verification error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        _print_report(report, args.session_file)

    return 0 if report.chain_valid else 1


if __name__ == "__main__":
    sys.exit(main())