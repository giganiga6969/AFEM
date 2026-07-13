"""
AFEM Integrity Package — public API
=====================================
Phase 2: Evidence Integrity via SHA-256 hash chaining.

Re-exports all public symbols so callers can write:

    from integrity import seal_session, verify_session, EvidenceTrust

Sub-module responsibilities
---------------------------
``integrity.hash_chain``
    Low-level primitives: canonical_json, compute_event_hash, chain_events,
    JSONL I/O helpers, is_sealed, GENESIS_HASH.

``integrity.sealer``
    Seals a completed session JSONL by adding previous_hash and event_hash
    to every event. Called by EvidenceCollector.log_session_end().

``integrity.verifier``
    Verifies a sealed session JSONL and produces an IntegrityReport.
    Called by scripts/verify_session.py and all future forensic phases.
"""
from __future__ import annotations

from integrity.hash_chain import GENESIS_HASH, compute_event_hash, is_sealed
from integrity.sealer import SealingError, seal_all_sessions, seal_session
from integrity.verifier import verify_session, verify_sessions_dir

__all__ = [
    # Constants
    "GENESIS_HASH",
    # Hash primitives
    "compute_event_hash",
    "is_sealed",
    # Sealing
    "seal_session",
    "seal_all_sessions",
    "SealingError",
    # Verification
    "verify_session",
    "verify_sessions_dir",
]