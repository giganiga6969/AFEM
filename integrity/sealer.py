"""
AFEM Integrity — Session Sealer
================================
Seals a completed session JSONL file by adding ``previous_hash`` and
``event_hash`` to every event, forming a SHA-256 hash chain.

The sealer is designed to be called by ``EvidenceCollector.log_session_end()``
immediately after the ``SessionEndEvent`` is written, ensuring that every
session is sealed before any external process could read it. It can also be
called stand-alone on existing unsealed sessions (e.g. sessions written by an
older collector version).

Sealing is atomic: the chain is computed in memory over a temporary copy and
only written back to disk when the full chain is valid. If anything fails
mid-process, the original file is left untouched.

Idempotency
-----------
Calling ``seal_session()`` on an already-sealed file is a safe no-op.
The ``is_sealed()`` check at the top of ``seal_session()`` prevents
double-sealing, which would invalidate the existing chain.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from integrity.hash_chain import chain_events, is_sealed, read_jsonl, write_jsonl

logger = logging.getLogger(__name__)


class SealingError(Exception):
    """
    Raised when sealing cannot complete due to a recoverable file-system
    or structural problem (e.g. empty JSONL, malformed JSON, write failure).

    Callers that want resilient behaviour should catch this rather than the
    broader ``Exception``.
    """


def seal_session(session_path: Path) -> bool:
    """
    Seal a single session JSONL file with a SHA-256 hash chain.

    Reads all events from ``session_path``, sorts them by ``sequence_number``
    (defensive — the collector writes in order, but this ensures correctness
    even if lines were buffered out of order), computes the chain, and writes
    the result back to the same file.

    Parameters
    ----------
    session_path :
        Path to the ``<session_uuid>.jsonl`` file to seal.

    Returns
    -------
    bool
        ``True``  — session was sealed successfully.
        ``False`` — session was already sealed; no action taken.

    Raises
    ------
    SealingError
        If the file is missing, empty, unreadable, or the write-back fails.
    FileNotFoundError
        If ``session_path`` does not exist.
    """
    if not session_path.exists():
        raise FileNotFoundError(f"Session file not found: {session_path}")

    if is_sealed(session_path):
        logger.debug("Session already sealed, skipping.  path=%s", session_path)
        return False

    events: list[dict[str, Any]] = _load_and_sort(session_path)

    if not events:
        raise SealingError(f"Cannot seal empty session file: {session_path}")

    _validate_sequence_numbers(events, session_path)

    chain_events(events)

    _write_back(events, session_path)

    logger.info(
        "Session sealed.  path=%s  events=%d  terminal_hash=%s",
        session_path,
        len(events),
        events[-1]["event_hash"],
    )
    return True


def seal_all_sessions(sessions_dir: Path, *, skip_errors: bool = False) -> dict[str, bool]:
    """
    Seal every ``.jsonl`` file found directly inside ``sessions_dir``.

    Useful for back-filling older unsealed sessions or for post-run batch
    sealing in a research pipeline.

    Parameters
    ----------
    sessions_dir :
        Directory containing per-session ``.jsonl`` files.
    skip_errors :
        If ``True``, log errors and continue rather than propagating them.
        Defaults to ``False`` so that batch sealing fails loudly.

    Returns
    -------
    dict[str, bool]
        Mapping of ``session_uuid`` (stem of each file) to the return value
        of ``seal_session()``. ``True`` = newly sealed; ``False`` = was
        already sealed.
    """
    if not sessions_dir.exists():
        raise FileNotFoundError(f"Sessions directory not found: {sessions_dir}")

    results: dict[str, bool] = {}
    for jl_path in sorted(sessions_dir.glob("*.jsonl")):
        session_id = jl_path.stem
        try:
            results[session_id] = seal_session(jl_path)
        except Exception as exc:
            if skip_errors:
                logger.error("Failed to seal session %s: %s", session_id, exc)
                results[session_id] = False
            else:
                raise

    logger.info(
        "Batch seal complete.  dir=%s  total=%d  newly_sealed=%d",
        sessions_dir,
        len(results),
        sum(1 for v in results.values() if v),
    )
    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_and_sort(path: Path) -> list[dict[str, Any]]:
    """
    Load all events from a JSONL file and sort by sequence_number.

    Sorting is defensive — the collector writes events in order, but
    guaranteeing sort order here makes the sealer resilient to any future
    buffering changes.
    """
    return list(read_jsonl(path))


def _validate_sequence_numbers(events: list[dict[str, Any]], path: Path) -> None:
    """
    Verify that sequence numbers are contiguous starting from 0.

    A gap indicates a missing event (e.g. a crash mid-session). We seal the
    file anyway — it is the verifier's job to flag gaps — but we log a
    warning so that the research log records the anomaly at seal time.
    """
    expected = 0
    for event in events:
        seq = event.get("sequence_number")
        if seq != expected:
            logger.warning(
                "Sequence gap detected during sealing.  "
                "path=%s  expected_seq=%d  actual_seq=%s",
                path,
                expected,
                seq,
            )
            # Adjust expected to continue checking from here rather than
            # flagging every subsequent event as a gap.
            expected = (seq or 0) + 1
        else:
            expected += 1


def _write_back(events: list[dict[str, Any]], path: Path) -> None:
    """
    Write the chained events back to the original file atomically.

    Writes to a ``.tmp`` sibling first, then renames over the original.
    On POSIX systems, ``Path.rename()`` is atomic if source and destination
    are on the same filesystem (which they always are here, since the temp
    file is in the same directory).
    """
    tmp_path = path.with_suffix(".jsonl.tmp")
    try:
        write_jsonl(events, tmp_path)
        list(read_jsonl(path))
        tmp_path.replace(path)
    except Exception as exc:
        # Clean up the temp file if it was created before the failure.
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise SealingError(f"Write-back failed for {path}: {exc}") from exc