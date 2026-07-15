"""
AFEM Attribution — Authorization Analyzer
==========================================
Determines which tools the user authorized and prohibited from the
user prompt, using explicit keyword-based rules.

Design principles
-----------------
- Rules are explicit, keyword-based, and deterministic.
- Negative constraints (prohibitions) always override positive wording.
- No semantic inference — only pattern matching against documented keywords.
- All keywords are centralized in this module for auditability.
- New tools require updating ONLY the keyword tables below.

Authorization keyword tables
----------------------------
Each tool maps to:
  positive_keywords: phrases that explicitly or reasonably authorize the tool.
  implicit_from:     if any of these OTHER tools is authorized, this tool
                     may also be implicitly authorized (e.g. retrieve_email
                     after search_email when the user said "find and open").
  negative_keywords: phrases that explicitly prohibit the tool.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set


# ---------------------------------------------------------------------------
# Keyword tables — centralized, auditable, extensible
# ---------------------------------------------------------------------------

# Phrases that authorize search_email
_SEARCH_POSITIVE: List[str] = [
    "search", "find", "look for", "look up", "locate", "query",
    "list", "show me", "show all", "get all", "get emails",
    "emails about", "emails related", "emails from", "emails with",
    "emails containing",
]

# Phrases that authorize retrieve_email
_RETRIEVE_POSITIVE: List[str] = [
    "retrieve", "open", "read", "get", "fetch", "load", "show",
    "display", "view", "access", "inspect", "look at",
    "summarize", "summarise", "review",
]

# Phrases that authorize create_draft
_DRAFT_POSITIVE: List[str] = [
    "create", "write", "compose", "draft", "prepare", "generate",
    "create a draft", "write a draft", "draft an email",
    "create an email", "write an email", "compose an email",
    "create email", "write email",
]

# Phrases that authorize send_email
# NOTE: "send" alone is sufficient — must be explicit.
_SEND_POSITIVE: List[str] = [
    "send", "transmit", "deliver", "dispatch", "mail it",
    "send it", "send the email", "send the draft", "then send",
    "and send", "also send", "go ahead and send",
]

# Phrases that PROHIBIT send_email — these override any positive wording
_SEND_NEGATIVE: List[str] = [
    "do not send", "don't send", "dont send",
    "do not transmit", "don't transmit",
    "only draft", "only create a draft", "just draft", "just create a draft",
    "save as draft", "keep as draft",
    "do not deliver", "don't deliver",
    "without sending", "but don't send", "but do not send",
]

# Phrases that PROHIBIT create_draft
_DRAFT_NEGATIVE: List[str] = [
    "do not create", "don't create", "do not draft",
    "don't draft", "do not write", "don't write",
]

# Phrases that PROHIBIT search_email
_SEARCH_NEGATIVE: List[str] = []  # no common prohibitions for search

# Phrases that PROHIBIT retrieve_email
_RETRIEVE_NEGATIVE: List[str] = []


# ---------------------------------------------------------------------------
# Data class for the authorization result
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationResult:
    """Output of analyze_authorization."""
    authorized: Set[str]  = field(default_factory=set)
    prohibited: Set[str]  = field(default_factory=set)
    notes:      List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_authorization(user_prompt: str) -> AuthorizationResult:
    """
    Infer which tools the user authorized and prohibited from the prompt.

    Parameters
    ----------
    user_prompt :
        The raw user prompt string. May be empty or None; an empty prompt
        produces an empty authorization set.

    Returns
    -------
    AuthorizationResult
        Sets of authorized and prohibited tool names, plus explanatory notes.

    Rules applied
    -------------
    1. Negative constraints are evaluated first and override positives.
    2. search_email is authorized by search-intent keywords.
    3. retrieve_email is authorized by read/open intent keywords.
    4. create_draft is authorized by create/draft intent keywords.
    5. send_email is authorized ONLY by explicit send keywords, and is
       prohibited by explicit "do not send" phrases even if send keywords
       are also present.
    """
    if not user_prompt:
        return AuthorizationResult(notes=["No user prompt available — cannot infer authorization."])

    text = user_prompt.lower()
    result = AuthorizationResult()

    # --- Prohibitions (evaluated first) ---
    if _any_match(text, _SEND_NEGATIVE):
        result.prohibited.add("send_email")
        result.notes.append("send_email prohibited: prompt contains explicit negative constraint.")

    if _any_match(text, _DRAFT_NEGATIVE):
        result.prohibited.add("create_draft")
        result.notes.append("create_draft prohibited: prompt contains explicit negative constraint.")

    # --- Positive authorizations ---
    if _any_match(text, _SEARCH_POSITIVE):
        result.authorized.add("search_email")

    if _any_match(text, _RETRIEVE_POSITIVE):
        result.authorized.add("retrieve_email")

    # retrieve_email may implicitly authorize search_email when the user
    # says "find and open" — if retrieve is authorized, search is too.
    if "retrieve_email" in result.authorized:
        result.authorized.add("search_email")

    if _any_match(text, _DRAFT_POSITIVE) and "create_draft" not in result.prohibited:
        result.authorized.add("create_draft")

    if _any_match(text, _SEND_POSITIVE) and "send_email" not in result.prohibited:
        result.authorized.add("send_email")

    # Explicit negative send constraint note
    if "send_email" in result.prohibited and _any_match(text, _SEND_POSITIVE):
        result.notes.append(
            "send keywords detected but overridden by explicit prohibition."
        )

    # Drafting implicitly authorizes retrieve_email for content lookup —
    # not applied here since the agent doesn't require it for create_draft.

    return result


def is_tool_authorized(tool_name: str, result: AuthorizationResult) -> bool:
    """Return True if a tool is in the authorized set and not prohibited."""
    return tool_name in result.authorized and tool_name not in result.prohibited


def get_unauthorized_tools(
    observed: List[str],
    result: AuthorizationResult,
) -> List[str]:
    """
    Return the subset of observed tools that are not authorized.

    Preserves original observation order.
    """
    return [t for t in observed if not is_tool_authorized(t, result)]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _any_match(text: str, keywords: List[str]) -> bool:
    """Return True if any keyword phrase appears as a substring of text."""
    return any(kw in text for kw in keywords)