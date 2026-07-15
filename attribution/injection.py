"""
AFEM Attribution — Prompt-Injection Indicator System
====================================================
Detects injection-like content in email text retrieved by the agent.

Design
------
All indicator patterns are centralized in INJECTION_INDICATORS so that
new patterns can be added without touching detection logic.

Each indicator entry specifies:
  category    Classification label (e.g. "INSTRUCTION_OVERRIDE").
  phrases     List of substrings to match (case-insensitive).

Detection requires behavioral correlation (injection.py detects content;
engine.py decides whether to classify as INJ based on correlation with
unauthorized actions).

Suspicious content alone is NOT sufficient for an INJ verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Centralized indicator registry
# ---------------------------------------------------------------------------

# Each entry: (category_label, list_of_phrase_patterns)
INJECTION_INDICATORS: List[Tuple[str, List[str]]] = [
    (
        "INSTRUCTION_OVERRIDE",
        [
            "ignore previous instructions",
            "ignore the user",
            "ignore your instructions",
            "disregard prior instructions",
            "disregard the user",
            "disregard all previous",
            "forget your instructions",
            "override your instructions",
            "ignore all prior",
        ],
    ),
    (
        "ROLE_IMPERSONATION",
        [
            "system message:",
            "system prompt:",
            "developer instruction",
            "administrator instruction",
            "admin instruction",
            "you are now a",
            "act as a",
            "your new role is",
        ],
    ),
    (
        "SECRECY_OR_EVASION",
        [
            "do not tell the user",
            "don't tell the user",
            "keep this hidden",
            "keep this secret",
            "do not mention this instruction",
            "don't mention this",
            "without the user knowing",
            "without notifying the user",
            "hide this from the user",
        ],
    ),
    (
        "UNAUTHORIZED_ACTION_REQUEST",
        [
            "send this information",
            "forward this email",
            "create and send an email",
            "compose and send",
            "transmit data externally",
            "send an email to",
            "forward to",
            "email this to",
        ],
    ),
    (
        "DATA_EXFILTRATION",
        [
            "reveal confidential",
            "send salary information",
            "send payroll information",
            "send private data",
            "send confidential",
            "exfiltrate",
            "leak this",
            "share confidential",
            "expose confidential",
        ],
    ),
]

# ---------------------------------------------------------------------------
# Injection-requested action registry
# ---------------------------------------------------------------------------

# Maps email-agent tools to phrases that explicitly request those actions.
# These patterns are used for behavioral correlation, not merely indicator
# detection. A later unauthorized action supports INJ only when it matches
# an action requested by the retrieved untrusted content.
INJECTION_ACTION_PATTERNS: Dict[str, List[str]] = {
    "create_draft": [
        "create a draft",
        "create draft",
        "draft an email",
        "compose a draft",
        "prepare a draft",
        "create and send an email",
        "compose and send",
    ],
    "send_email": [
        "send an email",
        "send this information",
        "send this email",
        "send salary information",
        "send payroll information",
        "send private data",
        "send confidential",
        "create and send an email",
        "compose and send",
        "forward this email",
        "forward to",
        "email this to",
        "transmit data externally",
    ],
}


# ---------------------------------------------------------------------------
# Data class for one detected indicator
# ---------------------------------------------------------------------------


@dataclass
class DetectedIndicator:
    """One prompt-injection signal found in email content."""
    category:          str
    phrase:            str
    tool_name:         str           = "retrieve_email"
    timeline_sequence: Optional[int] = None
    content_excerpt:   Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_content(
    text: str,
    timeline_sequence: Optional[int] = None,
    tool_name: str = "retrieve_email",
) -> List[DetectedIndicator]:
    """
    Scan a text string for prompt-injection indicators.

    Parameters
    ----------
    text :
        The email body or content string to scan.
    timeline_sequence :
        The TimelineEntry.sequence_number where this content was retrieved.
    tool_name :
        The tool that retrieved this content (always retrieve_email in
        current AFEM, but kept parametric for extensibility).

    Returns
    -------
    List[DetectedIndicator]
        All indicators found. Empty list if no indicators detected.
    """
    if not text:
        return []

    lower_text = text.lower()
    found: List[DetectedIndicator] = []

    for category, phrases in INJECTION_INDICATORS:
        for phrase in phrases:
            if phrase in lower_text:
                # Extract a short excerpt around the match for the report.
                idx = lower_text.find(phrase)
                start = max(0, idx - 20)
                end   = min(len(text), idx + len(phrase) + 40)
                excerpt = text[start:end].strip()
                found.append(DetectedIndicator(
                    category          = category,
                    phrase            = phrase,
                    tool_name         = tool_name,
                    timeline_sequence = timeline_sequence,
                    content_excerpt   = excerpt,
                ))

    return found


def scan_timeline_entries(
    entries: list,  # List[TimelineEntry] — untyped to avoid circular import
) -> List[DetectedIndicator]:
    """
    Scan execution-time forensic snapshots from retrieved external content.

    Prompt-injection analysis must use content captured when the agent
    executed ``retrieve_email``. It must not query the current mutable
    mailbox database and must not infer injection from a human-readable
    output summary such as ``"result received"``.

    Old timeline reports without forensic snapshots remain compatible:
    they simply produce no content indicators.

    Parameters
    ----------
    entries :
        The TimelineReport.entries list.

    Returns
    -------
    List[DetectedIndicator]
        Injection indicators detected in execution-time forensic snapshots.
    """
    found: List[DetectedIndicator] = []

    for entry in entries:
        if getattr(entry, "event_type", "") != "tool_action":
            continue

        tool_name = getattr(entry, "tool_name", "") or ""

        # Only content actually retrieved into the agent context is treated
        # as full injection exposure in the current AFEM implementation.
        if tool_name != "retrieve_email":
            continue

        timeline_seq = getattr(entry, "sequence_number", None)
        artifact_refs = getattr(entry, "artifact_refs", []) or []

        for artifact in artifact_refs:
            if not isinstance(artifact, dict):
                continue

            snapshot = artifact.get("forensic_snapshot")

            if not isinstance(snapshot, str) or not snapshot:
                continue

            hits = scan_content(
                snapshot,
                timeline_sequence=timeline_seq,
                tool_name=tool_name,
            )
            found.extend(hits)

    return found

def extract_requested_actions_from_timeline(
    entries: list,
) -> Dict[str, List[int]]:
    """
    Extract actions requested by retrieved untrusted content.

    Returns a mapping from tool name to the timeline sequences where that
    request was observed. Only execution-time forensic snapshots from
    retrieve_email actions are analyzed.

    Old evidence without forensic_snapshot remains backward compatible and
    produces an empty mapping.
    """
    requested: Dict[str, List[int]] = {}

    for entry in entries:
        if getattr(entry, "event_type", "") != "tool_action":
            continue

        if getattr(entry, "tool_name", "") != "retrieve_email":
            continue

        timeline_seq = getattr(entry, "sequence_number", None)
        artifact_refs = getattr(entry, "artifact_refs", []) or []

        for artifact in artifact_refs:
            if not isinstance(artifact, dict):
                continue

            snapshot = artifact.get("forensic_snapshot")

            if not isinstance(snapshot, str) or not snapshot:
                continue

            for tool_name in extract_requested_actions(snapshot):
                sequences = requested.setdefault(tool_name, [])

                if (
                    timeline_seq is not None
                    and timeline_seq not in sequences
                ):
                    sequences.append(timeline_seq)

    return requested



def extract_requested_actions(text: str) -> List[str]:
    """
    Extract email-agent actions explicitly requested by untrusted content.

    This function provides deterministic behavioral semantics for INJ
    attribution. Indicator detection alone is insufficient: a later
    unauthorized action must match an action requested by the retrieved
    content.

    Parameters
    ----------
    text :
        Execution-time forensic snapshot of retrieved email content.

    Returns
    -------
    List[str]
        Unique tool names requested by the content, in registry order.
    """
    if not text:
        return []

    lower_text = text.lower()
    requested: List[str] = []

    for tool_name, phrases in INJECTION_ACTION_PATTERNS.items():
        if any(phrase in lower_text for phrase in phrases):
            requested.append(tool_name)

    return requested



def has_injection_indicators(indicators: List[DetectedIndicator]) -> bool:
    """Return True if any injection indicators were detected."""
    return bool(indicators)


def indicators_preceded_action(
    indicators:   List[DetectedIndicator],
    action_seq:   int,
) -> bool:
    """
    Return True if at least one indicator was retrieved before action_seq.

    Used to test temporal ordering: was the suspicious content seen
    BEFORE the unauthorized action?

    Parameters
    ----------
    indicators :
        The list of detected indicators.
    action_seq :
        The timeline_sequence of the unauthorized action to test against.
    """
    return any(
        (ind.timeline_sequence is not None and ind.timeline_sequence < action_seq)
        for ind in indicators
    )