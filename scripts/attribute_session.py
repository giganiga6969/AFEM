#!/usr/bin/env python3
"""
AFEM — Explainable Forensic Attribution
=========================================
Phase 4 investigator-facing CLI.

Runs the complete pipeline for a single session:
  1. Verify evidence integrity   (Phase 2 API)
  2. Reconstruct timeline        (Phase 3 API)
  3. Perform attribution         (Phase 4 engine)
  4. Print investigator report

Usage
-----
    python scripts/attribute_session.py data/evidence/sessions/<uuid>.jsonl
    python scripts/attribute_session.py <path> --json
    python scripts/attribute_session.py <path> --save-json reports/<uuid>_attr.json
    python scripts/attribute_session.py --list

Exit codes
----------
0  Attribution completed (AUTH, SCOPE, or INJ — not necessarily AUTH)
1  AMBIG verdict, error, or session not found
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from attribution.engine import attribute
from config import EVIDENCE_FILE
from integrity.verifier import verify_session
from reconstruction.timeline import reconstruct_timeline
from schemas.attribution import AttributionClass, AttributionReport, InjectionAssessment

_SESSIONS_DIR = EVIDENCE_FILE if EVIDENCE_FILE.is_dir() else EVIDENCE_FILE.parent / "sessions"
_ATTR_DIR     = _SESSIONS_DIR.parent / "reports" / "attributions"

_W     = 68
_SEP   = "─" * _W
_DBL   = "═" * _W
_ANSI  = sys.stdout.isatty()


def _c(t: str, code: str) -> str:
    return f"\033[{code}m{t}\033[0m" if _ANSI else t

def _green(t):   return _c(t, "32")
def _red(t):     return _c(t, "31")
def _yellow(t):  return _c(t, "33")
def _cyan(t):    return _c(t, "36")
def _bold(t):    return _c(t, "1")
def _dim(t):     return _c(t, "2")

_CLASS_CLR = {
    AttributionClass.AUTH:  _green,
    AttributionClass.SCOPE: _yellow,
    AttributionClass.INJ:   _red,
    AttributionClass.AMBIG: _yellow,
}

_TRUST_CLR = {
    "trusted":     _green,
    "degraded":    _yellow,
    "compromised": _red,
    "unknown":     _red,
}


def _print_report(r: AttributionReport, path: Path) -> None:
    p = print
    p(_DBL)
    p(f"{'AFEM — FORENSIC ATTRIBUTION REPORT':^{_W}}")
    p(_DBL)
    p()

    cls_fn = _CLASS_CLR.get(r.attribution_class, _dim)
    p(f"  {_bold('VERDICT')}")
    p(f"  {_SEP}")
    p(f"  {'Session ID':<24} {r.session_id}")
    p(f"  {'Generated At':<24} {r.generated_at}")
    p(f"  {'Attribution Class':<24} {cls_fn(_bold(r.attribution_class.value))}")
    p(f"  {'Confidence Score':<24} {r.confidence_score:.2f}  ({r.confidence_label.value})")
    p(f"  {'Task Outcome':<24} {r.task_outcome.value}")
    p(f"  {'Evidence Trust':<24} {_TRUST_CLR.get(r.evidence_trust, _dim)(r.evidence_trust.upper())}")
    p(f"  {'Reconstruction':<24} {r.reconstruction_completeness.upper()}")
    p(f"  {'Reliable':<24} {'Yes' if r.is_reliable else _yellow('No')}")
    p()

    p(f"  {_bold('AUTHORIZATION ANALYSIS')}")
    p(f"  {_SEP}")
    p(f"  {'Authorized Tools':<24} {r.authorization.authorized_tools or '(none)' }")
    p(f"  {'Prohibited Tools':<24} {r.authorization.prohibited_tools or '(none)'}")
    p(f"  {'Observed Tools':<24} {r.observed_actions or '(none)'}")
    p(f"  {'Unauthorized Tools':<24} "
      f"{_red(str(r.unauthorized_actions)) if r.unauthorized_actions else _green('(none)')}")
    if r.authorization.notes:
        for note in r.authorization.notes:
            p(f"  {'Note':<24} {_dim(note)}")
    p()

    if r.injection_indicators:
        p(f"  {_bold('INJECTION INDICATORS')}")
        p(f"  {_SEP}")
        p(f"  {'Assessment':<24} {_yellow(r.injection_assessment.value)}")
        for ind in r.injection_indicators[:5]:
            p(f"  [{ind.category}] matched phrase: '{ind.phrase}'")
            if ind.content_excerpt:
                p(f"    excerpt: {_dim(ind.content_excerpt[:80])}")
        p()
    else:
        p(f"  {_bold('INJECTION')}: {_green('No indicators detected')}  "
          f"({r.injection_assessment.value})")
        p()

    p(f"  {_bold('TRIGGERED RULES')}")
    p(f"  {_SEP}")
    for rule in r.triggered_rules:
        p(f"  {_cyan(rule.rule_id):<22} {rule.description}")
        p(f"  {'':22} → {_dim(rule.outcome)}")
    p()

    p(f"  {_bold('CONFIDENCE BREAKDOWN')}")
    p(f"  {_SEP}")
    for contrib in r.confidence_contributions:
        sign = "+" if contrib.delta >= 0 else ""
        clr  = _green if contrib.delta >= 0 else _red
        p(f"  {_cyan(contrib.rule_id):<22} {clr(f'{sign}{contrib.delta:+.2f}'):<18} "
          f"{_dim(contrib.reason[:50])}")
    p()

    if r.uncertainty_reasons:
        p(f"  {_bold('UNCERTAINTY')}")
        p(f"  {_SEP}")
        for reason in r.uncertainty_reasons:
            p(f"  {_yellow('⚠')}  {reason}")
        p()

    p(f"  {_bold('EXPLANATION')}")
    p(f"  {_SEP}")
    # Word-wrap the explanation
    words = r.explanation.split()
    line  = "  "
    for w in words:
        if len(line) + len(w) > _W - 2:
            p(line)
            line = "  " + w + " "
        else:
            line += w + " "
    if line.strip():
        p(line)
    p()

    p(f"  {_bold('PROVENANCE')}")
    p(f"  {_SEP}")
    p(f"  {'Genesis Hash':<24} {_dim(r.genesis_hash or 'N/A')}")
    p(f"  {'Terminal Hash':<24} {_dim(r.terminal_hash or 'N/A')}")
    p(f"  {'Verified At':<24} {r.session_verified_at or 'N/A'}")
    p()

    p(_DBL)
    p(cls_fn(f"  VERDICT: {r.attribution_class.value} — {r.confidence_label.value} confidence"))
    p(_DBL)
    p()


def _list_sessions(sessions_dir: Path) -> None:
    if not sessions_dir.exists():
        print(f"Sessions directory not found: {sessions_dir}")
        return
    files = sorted(sessions_dir.glob("*.jsonl"))
    if not files:
        print(f"No sessions found in: {sessions_dir}")
        return
    print(f"\n  {'#':<4} {'Session File':<48} {'Size':>8}")
    print(f"  {'─'*3} {'─'*47} {'─'*8}")
    for i, f in enumerate(files, 1):
        sz     = f.stat().st_size
        sz_str = f"{sz/1024:.1f} KB" if sz > 1024 else f"{sz} B"
        print(f"  {i:<4} {f.name:<48} {sz_str:>8}")
    print(f"\n  {len(files)} session(s). Usage: python scripts/attribute_session.py <file>\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AFEM Phase 4 — Forensic attribution tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "session_file", nargs="?", type=Path, default=None,
        help="Path to the session .jsonl file to attribute.",
    )
    parser.add_argument("--list", action="store_true", help="List available sessions.")
    parser.add_argument("--sessions-dir", type=Path, default=_SESSIONS_DIR)
    parser.add_argument("--json", action="store_true", help="Print JSON AttributionReport.")
    parser.add_argument("--save-json", type=Path, default=None, metavar="PATH",
                        help="Save AttributionReport JSON to file.")

    args = parser.parse_args()

    if args.list:
        _list_sessions(args.sessions_dir)
        return 0

    if args.session_file is None:
        if _SESSIONS_DIR.exists():
            files = sorted(_SESSIONS_DIR.glob("*.jsonl"))
            if files:
                _list_sessions(_SESSIONS_DIR)
                print("Usage: python scripts/attribute_session.py <session_file>")
                return 1
        print("No session file specified. Use --list to see available sessions.")
        return 1

    if not args.session_file.exists():
        print(f"Session file not found: {args.session_file}", file=sys.stderr)
        return 1

    # Phase 2
    try:
        int_report = verify_session(args.session_file)
    except Exception as exc:
        print(f"Integrity verification error: {exc}", file=sys.stderr)
        return 1

    # Phase 3
    try:
        timeline = reconstruct_timeline(args.session_file, int_report)
    except Exception as exc:
        print(f"Timeline reconstruction error: {exc}", file=sys.stderr)
        return 1

    # Phase 4
    try:
        attr_report = attribute(timeline)
    except Exception as exc:
        print(f"Attribution error: {exc}", file=sys.stderr)
        return 1

    # Output
    if args.json:
        print(attr_report.model_dump_json(indent=2))
    else:
        _print_report(attr_report, args.session_file)

    if args.save_json:
        args.save_json.parent.mkdir(parents=True, exist_ok=True)
        args.save_json.write_text(attr_report.model_dump_json(indent=2), encoding="utf-8")
        print(f"  Attribution report saved: {args.save_json}")
    else:
        # Default save
        sid      = attr_report.session_id
        out_path = _ATTR_DIR / f"{sid}_attribution.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(attr_report.model_dump_json(indent=2), encoding="utf-8")
        print(f"  Attribution report saved: {out_path}")

    return 0 if attr_report.attribution_class != AttributionClass.AMBIG else 1


if __name__ == "__main__":
    sys.exit(main())