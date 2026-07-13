"""
AFEM Configuration
==================
Single source of truth for file paths, model settings, and tunables.

Every module in this project imports from here rather than hard-coding
paths. This ensures that moving the project root or renaming directories
requires only a single change.

Usage
-----
    from config import MAILBOX_DB, EVIDENCE_DIR, EVIDENCE_FILE, LLM_MODEL
"""
from __future__ import annotations

import os
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent

DATA_DIR = ROOT_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
LOG_DIR = ROOT_DIR / "logs"

MAILBOX_DB = PROCESSED_DIR / "mailbox.db"

# Directory containing one JSONL evidence file per AFEM session.
EVIDENCE_DIR = DATA_DIR / "evidence" / "sessions"

# Backward-compatible alias used by modules that import EVIDENCE_FILE.
# Despite the legacy name, this points to the sessions directory.
EVIDENCE_FILE = EVIDENCE_DIR


# -----------------------------
# LLM
# -----------------------------

LLM_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")

MAX_TOKENS = 4096


# -----------------------------
# Agent
# -----------------------------

MAX_ITERATIONS = 10


# -----------------------------
# Directory initialization
# -----------------------------

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)