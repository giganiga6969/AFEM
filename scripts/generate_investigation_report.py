"""
AFEM Phase 5 — Investigation Report Generator CLI.

Runs the existing AFEM forensic pipeline:

Session evidence
    -> integrity verification
    -> timeline reconstruction
    -> behavioral attribution
    -> InvestigationReport
    -> authoritative JSON
    -> investigator-facing HTML
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


# Permit direct execution from the repository root:
#
# python .\scripts\generate_investigation_report.py <session>
#
ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from config import EVIDENCE_DIR, INVESTIGATIONS_DIR
from integrity.verifier import verify_session
from reconstruction.timeline import reconstruct_timeline
from attribution.engine import attribute
from reporting.investigation import generate_investigation_report


def _build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Generate authoritative JSON and investigator-facing HTML "
            "reports for one AFEM forensic evidence session."
        )
    )

    parser.add_argument(
        "session",
        help=(
            "Session ID or path to a session JSONL evidence file."
        ),
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=INVESTIGATIONS_DIR,
        help=(
            "Directory for generated JSON and HTML investigation "
            "reports. Defaults to the configured AFEM investigation "
            "report directory."
        ),
    )

    return parser


def _resolve_session_path(session: str) -> Path:
    """
    Resolve either a session ID or an explicit evidence-file path.
    """

    supplied_path = Path(session).expanduser()

    # Treat JSONL input, absolute input, or an existing filesystem
    # location as an explicit path.
    if (
        supplied_path.suffix.lower() == ".jsonl"
        or supplied_path.is_absolute()
        or supplied_path.exists()
    ):
        return supplied_path.resolve()

    # Otherwise interpret the argument as an AFEM session ID.
    return (
        EVIDENCE_DIR
        / f"{session}.jsonl"
    ).resolve()


def _display_value(value: object) -> str:
    """
    Return an enum's value when available; otherwise return text.
    """

    enum_value = getattr(value, "value", None)

    if enum_value is not None:
        return str(enum_value)

    return str(value)


def main() -> int:
    """Run the complete Phase 2 -> Phase 5 reporting pipeline."""

    parser = _build_parser()
    args = parser.parse_args()

    session_path = _resolve_session_path(args.session)
    output_dir = args.output_dir.expanduser().resolve()

    if not session_path.is_file():
        print(
            f"Error: session evidence file not found: {session_path}",
            file=sys.stderr,
        )
        return 1

    try:
        integrity_report = verify_session(session_path)

        timeline_report = reconstruct_timeline(
            session_path,
            integrity_report,
        )

        attribution_report = attribute(
            timeline_report
        )

        report, json_path, html_path = (
            generate_investigation_report(
                timeline_report=timeline_report,
                attribution_report=attribution_report,
                source_session_path=session_path,
                output_dir=output_dir,
            )
        )

    except Exception as exc:
        print(
            "Error: investigation report generation failed: "
            f"{exc}",
            file=sys.stderr,
        )
        return 1

    print("AFEM investigation report generated successfully.")
    print(f"Session ID: {report.session_id}")
    print(f"Integrity Status: {report.integrity_status}")
    print(f"Evidence Trust: {report.evidence_trust}")
    print(
        "Reconstruction Completeness: "
        f"{report.reconstruction_completeness}"
    )
    print(
        "Attribution Class: "
        f"{_display_value(report.attribution_class)}"
    )
    print(f"Confidence Score: {report.confidence_score:.2f}")
    print(
        "Confidence Label: "
        f"{_display_value(report.confidence_label)}"
    )
    print(f"Reliable: {report.reliable}")
    print(f"JSON Report: {json_path}")
    print(f"HTML Report: {html_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())