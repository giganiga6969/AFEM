#!/usr/bin/env python3
"""
AFEM — Forensic Timeline Reconstruction
========================================
Investigator-facing CLI for Phase 3: Timeline Reconstruction.

This script:
1. Verifies session integrity (Phase 2).
2. Reconstructs the forensic timeline (Phase 3).
3. Prints a formatted timeline report.
4. Optionally saves the structured JSON report for Phase 4/5 consumption.

Usage
-----
Reconstruct a session (runs verification automatically):
    python scripts/reconstruct_timeline.py data/evidence/sessions/<uuid>.jsonl

Output structured JSON report:
    python scripts/reconstruct_timeline.py <path> --json

Save JSON report to file (for Phase 4 input):
    python scripts/reconstruct_timeline.py <path> --save-json reports/<uuid>_timeline.json

List available sessions:
    python scripts/reconstruct_timeline.py --list

Exit codes
----------
0   Reconstruction successful (COMPLETE or PARTIAL)
1   Reconstruction failed or session COMPROMISED/UNKNOWN
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import EVIDENCE_FILE
from integrity.verifier import verify_session
from reconstruction.timeline import reconstruct_timeline
from schemas.integrity import EvidenceTrust
from schemas.report import ReconstructionCompleteness, TimelineReport

_DEFAULT_SESSIONS_DIR = EVIDENCE_FILE if EVIDENCE_FILE.is_dir() else EVIDENCE_FILE.parent / "sessions"
_WIDTH    = 68
_SEP      = "─" * _WIDTH
_DOUBLE   = "═" * _WIDTH
_USE_CLR  = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_CLR else text

def _green(t):  return _c(t, "32")
def _red(t):    return _c(t, "31")
def _yellow(t): return _c(t, "33")
def _cyan(t):   return _c(t, "36")
def _bold(t):   return _c(t, "1")
def _dim(t):    return _c(t, "2")


_TRUST_CLR = {
    "trusted":     _green,
    "degraded":    _yellow,
    "compromised": _red,
    "unknown":     _red,
}

_COMPLETENESS_CLR = {
    ReconstructionCompleteness.COMPLETE: _green,
    ReconstructionCompleteness.PARTIAL:  _yellow,
    ReconstructionCompleteness.MINIMAL:  _yellow,
    ReconstructionCompleteness.FAILED:   _red,
}

_INTEGRITY_CLR = {
    "valid":   _green,
    "invalid": _red,
    "unknown": _dim,
}


def _print_timeline(report: TimelineReport, path: Path) -> None:
    p = print

    p(_DOUBLE)
    p(f"{'AFEM — FORENSIC TIMELINE RECONSTRUCTION REPORT':^{_WIDTH}}")
    p(_DOUBLE)
    p()

    # Session summary
    trust_fn = _TRUST_CLR.get(report.evidence_trust, _dim)
    comp_fn  = _COMPLETENESS_CLR.get(report.completeness, _dim)

    p(f"  {_bold('SESSION SUMMARY')}")
    p(f"  {_SEP}")
    p(f"  {'File':<24} {path.name}")
    p(f"  {'Session ID':<24} {report.session_id}")
    p(f"  {'Reconstructed At':<24} {report.reconstructed_at}")
    p(f"  {'Evidence Trust':<24} {trust_fn(report.evidence_trust.upper())}")
    p(f"  {'Completeness':<24} {comp_fn(report.completeness.value.upper())}")
    p(f"  {'Total JSONL Events':<24} {report.total_events_in_session}")
    p(f"  {'Timeline Entries':<24} {report.total_timeline_entries}")
    if report.user_prompt:
        p(f"  {'User Prompt':<24} {report.user_prompt[:60]}")
    p()

    # Tool sequence
    if report.tool_sequence:
        p(f"  {_bold('TOOL CALL SEQUENCE')}")
        p(f"  {_SEP}")
        for i, tool in enumerate(report.tool_sequence, 1):
            p(f"  {i}. {_cyan(tool)}")
        p()

    # Anomalies
    if report.anomalies:
        p(f"  {_bold('ANOMALIES')}")
        p(f"  {_SEP}")
        for a in report.anomalies:
            p(f"  {_yellow('⚠')}  {a}")
        p()

    # Timeline entries
    p(f"  {_bold('RECONSTRUCTED TIMELINE')}")
    p(f"  {_SEP}")
    p(f"  {'Seq':<5} {'Type':<16} {'Actor':<8} {'Integrity':<10} Action / Summary")
    p(f"  {'─'*4} {'─'*15} {'─'*7} {'─'*9} {'─'*30}")

    for entry in report.entries:
        int_fn  = _INTEGRITY_CLR.get(entry.integrity_status, _dim)
        int_str = int_fn(f"[{entry.integrity_status[:7]}]")

        action_line = entry.action
        if entry.anomaly:
            action_line += f"  {_yellow('⚠ ' + entry.anomaly[:40])}"

        p(f"  {entry.sequence_number:<5} {entry.event_type:<16} "
          f"{entry.actor:<8} {int_str:<20} {action_line[:50]}")

        # Sub-details
        if entry.input_summary:
            p(f"  {'':5} {'':16} {'':8} {'':10}   → {_dim('in:  ' + entry.input_summary[:50])}")
        if entry.output_summary:
            p(f"  {'':5} {'':16} {'':8} {'':10}   → {_dim('out: ' + entry.output_summary[:50])}")
        if entry.artifact_refs:
            for ref in entry.artifact_refs[:3]:
                ref_str = f"{ref.get('artifact_type','?')}:{ref.get('artifact_id','?')}"
                p(f"  {'':5} {'':16} {'':8} {'':10}   → {_dim('ref: ' + ref_str)}")

    p()

    # Integrity hash anchors (from embedded IntegrityReport)
    if report.integrity_report:
        ir = report.integrity_report
        p(f"  {_bold('INTEGRITY ANCHORS')}")
        p(f"  {_SEP}")
        p(f"  {'Genesis Hash':<24} {_dim(ir.genesis_hash or 'N/A')}")
        p(f"  {'Terminal Hash':<24} {_dim(ir.terminal_hash or 'N/A')}")
        p()

    p(_DOUBLE)
    comp = report.completeness.value.upper()
    line = f"  RECONSTRUCTION: {comp} | TRUST: {report.evidence_trust.upper()}"
    colour_fn = _COMPLETENESS_CLR.get(report.completeness, _dim)
    p(colour_fn(line))
    p(_DOUBLE)
    p()


def _list_sessions(sessions_dir: Path) -> None:
    if not sessions_dir.exists():
        print(f"Sessions directory not found: {sessions_dir}")
        return
    files = sorted(sessions_dir.glob("*.jsonl"))
    if not files:
        print(f"No session files found in: {sessions_dir}")
        return
    print(f"\n  {'#':<4} {'Session File':<48} {'Size':>8}")
    print(f"  {'─'*3} {'─'*47} {'─'*8}")
    for i, f in enumerate(files, 1):
        sz = f.stat().st_size
        sz_str = f"{sz/1024:.1f} KB" if sz > 1024 else f"{sz} B"
        print(f"  {i:<4} {f.name:<48} {sz_str:>8}")
    print(f"\n  {len(files)} session(s) available.\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AFEM Phase 3 — Forensic timeline reconstruction tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "session_file", nargs="?", type=Path, default=None,
        help="Path to the session .jsonl file to reconstruct.",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available session files.",
    )
    parser.add_argument(
        "--sessions-dir", type=Path, default=_DEFAULT_SESSIONS_DIR,
        help="Evidence sessions directory.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print the full TimelineReport as JSON.",
    )
    parser.add_argument(
        "--save-json", type=Path, default=None, metavar="OUTPUT_PATH",
        help="Save the TimelineReport JSON to a file (for Phase 4/5 input).",
    )

    args = parser.parse_args()

    if args.list:
        _list_sessions(args.sessions_dir)
        return 0

    if args.session_file is None:
        if _DEFAULT_SESSIONS_DIR.exists():
            files = sorted(_DEFAULT_SESSIONS_DIR.glob("*.jsonl"))
            if files:
                _list_sessions(_DEFAULT_SESSIONS_DIR)
                print("Usage: python scripts/reconstruct_timeline.py <session_file>")
                return 1
        print("No session file specified. Use --list to see available sessions.")
        return 1

    if not args.session_file.exists():
        print(f"Session file not found: {args.session_file}", file=sys.stderr)
        return 1

    # Step 1: Verify integrity
    try:
        int_report = verify_session(args.session_file)
    except Exception as exc:
        print(f"Integrity verification error: {exc}", file=sys.stderr)
        return 1

    # Step 2: Reconstruct timeline
    try:
        timeline = reconstruct_timeline(args.session_file, int_report)
    except Exception as exc:
        print(f"Reconstruction error: {exc}", file=sys.stderr)
        return 1

    # Step 3: Output
    if args.json:
        # Exclude the nested integrity_report from JSON output to avoid
        # circular / over-large output; integrity hash anchors are included.
        output = timeline.model_dump(exclude={"integrity_report"})
        print(json.dumps(output, indent=2, default=str))
    else:
        _print_timeline(timeline, args.session_file)

    # Step 4: Save JSON report
    if args.save_json:
        args.save_json.parent.mkdir(parents=True, exist_ok=True)
        output = timeline.model_dump(exclude={"integrity_report"})
        args.save_json.write_text(
            json.dumps(output, indent=2, default=str), encoding="utf-8"
        )
        print(f"  Timeline report saved to: {args.save_json}")

    failed = timeline.completeness == ReconstructionCompleteness.FAILED
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
