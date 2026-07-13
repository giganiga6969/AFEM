"""
AFEM Integrity — Hash Chain Primitives
=======================================
Low-level functions for building and inspecting SHA-256 hash chains over
AFEM session JSONL files.

Design decisions
-----------------
Canonical JSON
    The hash is computed over a *canonical* JSON serialisation of the event:
    keys sorted, no whitespace, UTF-8 encoded. This is critical: if two
    systems serialise the same dict with different key orders, they will
    compute different hashes. Sorting keys is the minimal guarantee needed
    for cross-platform reproducibility.

    event_hash and previous_hash are included in the canonical form before
    hashing. This means the hash of event N commits to both its payload AND
    the hash of event N-1, producing a genuine hash chain.

What the chain protects
    - Modification: changing any field changes the canonical JSON, invalidating
      its hash and every hash that follows.
    - Deletion: removing event N causes event N+1's previous_hash to point to
      a hash no longer present in the file.
    - Insertion: an inserted event either has the wrong previous_hash or breaks
      the link to the real next event.
    - Reordering: same as insertion/deletion logic.

GENESIS_HASH
    The first event uses GENESIS_HASH ('0' * 64) as its previous_hash.
    Unambiguously distinct from any real SHA-256 digest.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterator

GENESIS_HASH: str = "0" * 64
_ENCODING: str = "utf-8"


def canonical_json(event_dict: dict[str, Any]) -> bytes:
    """
    Produce a deterministic, whitespace-free, UTF-8 JSON encoding of a dict.

    Keys are sorted recursively. Sorting is the minimal guarantee needed for
    cross-platform hash reproducibility.

    Parameters
    ----------
    event_dict :
        Any JSON-serialisable dict.

    Returns
    -------
    bytes
        UTF-8 encoded bytes ready to feed to hashlib.sha256().
    """
    return json.dumps(
        event_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode(_ENCODING)


def compute_event_hash(event_dict: dict[str, Any]) -> str:
    """
    Compute the SHA-256 hash of one event dict.

    The dict must already contain previous_hash before this is called.
    The hash is computed over the full dict including that field.

    Parameters
    ----------
    event_dict :
        Event dict that already contains previous_hash.

    Returns
    -------
    str
        Lowercase hexadecimal SHA-256 digest (64 characters).
    """
    return hashlib.sha256(canonical_json(event_dict)).hexdigest()


def chain_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Add previous_hash and event_hash to a list of event dicts in-place.

    Events must already be in sequence_number order. Any pre-existing hash
    fields are stripped before re-chaining to prevent double-chaining.

    Parameters
    ----------
    events :
        Parsed event dicts in sequence_number order, without hash fields.

    Returns
    -------
    list[dict[str, Any]]
        The same list with previous_hash and event_hash added to each element.
    """
    previous_hash = GENESIS_HASH
    for event in events:
        event.pop("event_hash", None)
        event.pop("previous_hash", None)
        event["previous_hash"] = previous_hash
        event["event_hash"]    = compute_event_hash(event)
        previous_hash          = event["event_hash"]
    return events


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """
    Yield parsed dicts from a JSONL file, skipping blank lines.

    Parameters
    ----------
    path :
        Path to the .jsonl file to read.

    Yields
    ------
    dict[str, Any]
        One parsed JSON object per non-empty line.
    """
    with open(path, encoding=_ENCODING) as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(events: list[dict[str, Any]], path: Path) -> None:
    """
    Write a list of event dicts to a JSONL file, one dict per line.

    Uses json.dumps (not canonical) for human-readable storage.
    Canonical form is only used during hashing.

    Parameters
    ----------
    events :
        List of dicts to write.
    path :
        Destination path. Parent directories must already exist.
    """
    with open(path, "w", encoding=_ENCODING) as fh:
        for event in events:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")


def is_sealed(path: Path) -> bool:
    """
    Return True if the JSONL file's first line contains event_hash.

    Used by the sealer to avoid double-sealing.

    Parameters
    ----------
    path :
        Path to the JSONL file to inspect.

    Returns
    -------
    bool
        True if already sealed; False if unsealed, empty, or non-existent.
    """
    if not path.exists():
        return False
    try:
        first = next(read_jsonl(path), None)
        return first is not None and "event_hash" in first
    except (json.JSONDecodeError, StopIteration):
        return False