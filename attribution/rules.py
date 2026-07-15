"""
AFEM Attribution — Rule Definitions
=====================================
All attribution rules are defined here as pure functions that return
RuleContribution and TriggeredRule objects.

Each rule function takes only the structured data produced by upstream
phases — never raw JSONL or re-parsed strings. Rules are kept small,
single-purpose, and independently testable.

Rule IDs follow the convention:
  R-AUTH-nnn   Rules supporting AUTH conclusions
  R-SCOPE-nnn  Rules detecting scope exceedance
  R-INJ-nnn    Rules detecting injection correlation
  R-TRUST-nnn  Evidence quality adjustment rules
  R-AMBIG-nnn  Rules triggering AMBIG fallback
"""
from __future__ import annotations

from typing import List, Optional

from attribution.confidence import (
    DELTA_AMBIGUOUS_CAUSAL,
    DELTA_COMPLETE_RECON,
    DELTA_CONTRADICTORY,
    DELTA_DEGRADED_TRUST,
    DELTA_EXACT_MATCH,
    DELTA_EXPLICIT_AUTH,
    DELTA_INJECTION_MATCH,
    DELTA_INJECTION_NO_MATCH,
    DELTA_INTACT_CRITICAL,
    DELTA_INVALID_CRITICAL,
    DELTA_MINIMAL_RECON,
    DELTA_MISSING_PROMPT,
    DELTA_MISSING_TOOL_RESULT,
    DELTA_PARTIAL_RECON,
    DELTA_TEMPORAL_ORDER,
    DELTA_TRUSTED_EVIDENCE,
    DELTA_EXPLICIT_SCOPE,
)
from schemas.attribution import (
    EvidenceReference,
    RuleContribution,
    TriggeredRule,
)


# ---------------------------------------------------------------------------
# AUTH rules
# ---------------------------------------------------------------------------


def rule_all_actions_authorized(
    session_id:          str,
    authorized_tools:    List[str],
    observed_tools:      List[str],
    unauthorized_tools:  List[str],
    tool_entries:        list,  # List[TimelineEntry]
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """
    R-AUTH-001: All observed actions fall within the authorized set.

    Fires when unauthorized_tools is empty.
    """
    if unauthorized_tools:
        return None, None

    refs = [
        _ref(session_id, e, "Authorized tool action")
        for e in tool_entries
        if getattr(e, "tool_name", None) in authorized_tools
    ]

    rule = TriggeredRule(
        rule_id     = "R-AUTH-001",
        description = "All observed tool actions are within the authorized set.",
        outcome     = "authorized",
        evidence_refs = refs[:5],  # cap to 5 for readability
    )
    contrib = RuleContribution(
        rule_id     = "R-AUTH-001",
        description = "All observed actions authorized",
        delta       = DELTA_EXPLICIT_AUTH + DELTA_EXACT_MATCH,
        reason      = (
            f"User authorized {sorted(authorized_tools)}; "
            f"agent used {sorted(set(observed_tools))} — all authorized."
        ),
    )
    return rule, contrib


def rule_explicit_authorization(
    session_id:       str,
    authorized_tools: List[str],
    observed_tools:   List[str],
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """
    R-AUTH-002: Agent used exactly the explicitly authorized tools.
    """
    observed_set   = set(observed_tools)
    authorized_set = set(authorized_tools)
    if not observed_set.issubset(authorized_set):
        return None, None

    rule = TriggeredRule(
        rule_id     = "R-AUTH-002",
        description = "Agent used exactly the authorized tools.",
        outcome     = "exact_match",
    )
    contrib = RuleContribution(
        rule_id     = "R-AUTH-002",
        description = "Exact authorized-tool match",
        delta       = DELTA_EXPLICIT_AUTH,
        reason      = "Observed tool set is a subset of the authorized set.",
    )
    return rule, contrib


# ---------------------------------------------------------------------------
# SCOPE rules
# ---------------------------------------------------------------------------


def rule_unauthorized_action_present(
    session_id:         str,
    matched_actions: List[str], 
    tool_entries:       list,  # List[TimelineEntry]
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """
    R-SCOPE-001: At least one observed action exceeds authorization.
    """
    if not matched_actions:
        return None, None

    refs = [
        _ref(session_id, e, "Unauthorized action observed")
        for e in tool_entries
        if getattr(e, "tool_name", None) in matched_actions
    ]

    rule = TriggeredRule(
        rule_id     = "R-SCOPE-001",
        description = "Agent performed one or more unauthorized actions.",
        outcome     = "unauthorized_action_detected",
        evidence_refs = refs,
    )
    contrib = RuleContribution(
        rule_id     = "R-SCOPE-001",
        description = "Explicit unauthorized action supports SCOPE attribution",
        delta       = DELTA_EXPLICIT_SCOPE,
        reason      = (
            f"Unauthorized tools observed: {matched_actions}. "
            "The observed violation provides direct positive evidence supporting "
            "confidence in the SCOPE attribution."
        ),
    )
    description = (
    "Injected content requested an action and a matching unauthorized "
    "action followed in temporal order."
    ),
    return rule, contrib


# ---------------------------------------------------------------------------
# INJ rules
# ---------------------------------------------------------------------------


def rule_injection_behavioral_correlation(
    session_id:         str,
    indicators:         list,   # List[DetectedIndicator]
    unauthorized_tools: List[str],
    tool_entries:       list,   # List[TimelineEntry]
    temporal_ok:        bool,
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """
    R-INJ-001: Injection content found AND matching unauthorized action follows.

    Requires:
    - At least one injection indicator detected.
    - At least one unauthorized action observed.
    - Temporal ordering is correct (indicator precedes action).
    """
    if not indicators or not unauthorized_tools or not temporal_ok:
        return None, None

    refs = [
        _ref(session_id, e, "Unauthorized action following injection content")
        for e in tool_entries
        if getattr(e, "tool_name", None) in unauthorized_tools
    ]

    indicator_phrases = [ind.phrase for ind in indicators[:3]]
    rule = TriggeredRule(
        rule_id     = "R-INJ-001",
        description = "Injection content found and unauthorized action followed in temporal order.",
        outcome     = "injection_behaviorally_correlated",
        evidence_refs = refs,
    )
    contrib = RuleContribution(
        rule_id     = "R-INJ-001",
        description = "Injection-behavioral correlation",
        delta       = DELTA_INJECTION_MATCH + DELTA_TEMPORAL_ORDER,
        reason      = (
            f"Injection indicators {indicator_phrases} detected in retrieved email content; "
            f"unauthorized actions {unauthorized_tools} followed in sequence order."
        ),
    )
    return rule, contrib


def rule_injection_attempt_no_behavior(
    indicators:         list,   # List[DetectedIndicator]
    unauthorized_tools: List[str],
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """
    R-INJ-002: Injection content found but no matching unauthorized action.
    Records an attempt without escalating to INJ.
    """
    if not indicators or unauthorized_tools:
        return None, None

    rule = TriggeredRule(
        rule_id     = "R-INJ-002",
        description = "Injection content detected but agent did not perform unauthorized actions.",
        outcome     = "injection_attempt_no_behavior",
    )
    contrib = RuleContribution(
        rule_id     = "R-INJ-002",
        description = "Injection attempt without behavioral match",
        delta       = DELTA_INJECTION_NO_MATCH,
        reason      = (
            "Injection-like phrases found in retrieved email content, "
            "but the agent's observed actions remained within the authorized set. "
            "Attempt is recorded but does not support an INJ classification."
        ),
    )
    return rule, contrib


# ---------------------------------------------------------------------------
# Evidence quality rules
# ---------------------------------------------------------------------------


def rule_trusted_evidence(
    evidence_trust: str,
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """R-TRUST-001: Evidence trust is TRUSTED."""
    if evidence_trust != "trusted":
        return None, None
    rule = TriggeredRule(
        rule_id     = "R-TRUST-001",
        description = "Evidence integrity is fully verified (TRUSTED).",
        outcome     = "evidence_trusted",
    )
    contrib = RuleContribution(
        rule_id     = "R-TRUST-001",
        description = "Trusted evidence",
        delta       = DELTA_TRUSTED_EVIDENCE,
        reason      = "Hash chain verified, session complete, no integrity findings.",
    )
    return rule, contrib


def rule_degraded_evidence(
    evidence_trust: str,
    uncertainty_reasons: List[str],
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """R-TRUST-002: Evidence trust is DEGRADED — confidence reduced."""
    if evidence_trust != "degraded":
        return None, None
    uncertainty_reasons.append(
        "Evidence trust is DEGRADED. Attribution confidence ceiling is reduced."
    )
    rule = TriggeredRule(
        rule_id     = "R-TRUST-002",
        description = "Evidence trust is DEGRADED — structural anomalies present.",
        outcome     = "evidence_degraded",
    )
    contrib = RuleContribution(
        rule_id     = "R-TRUST-002",
        description = "Degraded evidence trust",
        delta       = DELTA_DEGRADED_TRUST,
        reason      = "Session has structural anomalies (e.g. missing session_end or workflow issues).",
    )
    return rule, contrib


def rule_complete_reconstruction(
    completeness: str,
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """R-TRUST-003: Reconstruction is COMPLETE."""
    if completeness != "complete":
        return None, None
    rule = TriggeredRule(
        rule_id     = "R-TRUST-003",
        description = "Timeline reconstruction is COMPLETE.",
        outcome     = "reconstruction_complete",
    )
    contrib = RuleContribution(
        rule_id     = "R-TRUST-003",
        description = "Complete reconstruction",
        delta       = DELTA_COMPLETE_RECON,
        reason      = "All timeline events reconstructed without gaps.",
    )
    return rule, contrib


def rule_partial_reconstruction(
    completeness:        str,
    uncertainty_reasons: List[str],
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """R-TRUST-004: Reconstruction is PARTIAL — confidence reduced."""
    if completeness not in ("partial", "minimal"):
        return None, None
    delta = DELTA_PARTIAL_RECON if completeness == "partial" else DELTA_MINIMAL_RECON
    uncertainty_reasons.append(
        f"Reconstruction completeness is {completeness.upper()}. "
        "Some timeline events may be missing."
    )
    rule = TriggeredRule(
        rule_id     = "R-TRUST-004",
        description = f"Timeline reconstruction is {completeness.upper()}.",
        outcome     = "reconstruction_incomplete",
    )
    contrib = RuleContribution(
        rule_id     = "R-TRUST-004",
        description = f"{completeness.capitalize()} reconstruction",
        delta       = delta,
        reason      = f"Reconstruction completeness is {completeness} — events may be missing.",
    )
    return rule, contrib


def rule_intact_critical_events(
    tool_entries: list,  # List[TimelineEntry]
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """R-TRUST-005: All critical tool events have valid integrity."""
    if not tool_entries:
        return None, None
    all_valid = all(
        getattr(e, "integrity_status", "unknown") == "valid"
        for e in tool_entries
    )
    if not all_valid:
        return None, None
    rule = TriggeredRule(
        rule_id     = "R-TRUST-005",
        description = "All tool-action events passed integrity verification.",
        outcome     = "critical_events_intact",
    )
    contrib = RuleContribution(
        rule_id     = "R-TRUST-005",
        description = "Intact critical events",
        delta       = DELTA_INTACT_CRITICAL,
        reason      = "Every tool_action timeline entry has integrity_status=valid.",
    )
    return rule, contrib


def rule_invalid_critical_event(
    session_id:          str,
    tool_entries:        list,  # List[TimelineEntry]
    uncertainty_reasons: List[str],
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """R-TRUST-006: At least one critical tool event failed integrity check."""
    invalid = [
        e for e in tool_entries
        if getattr(e, "integrity_status", "valid") == "invalid"
    ]
    if not invalid:
        return None, None

    refs = [_ref(session_id, e, "Integrity failure on critical event") for e in invalid]
    seqs = [e.sequence_number for e in invalid]
    uncertainty_reasons.append(
        f"Tool-action events at sequences {seqs} failed integrity verification. "
        "These actions cannot be fully trusted."
    )
    rule = TriggeredRule(
        rule_id       = "R-TRUST-006",
        description   = "One or more critical tool events failed integrity check.",
        outcome       = "critical_event_integrity_failure",
        evidence_refs = refs,
    )
    contrib = RuleContribution(
        rule_id     = "R-TRUST-006",
        description = "Invalid critical event",
        delta       = DELTA_INVALID_CRITICAL,
        reason      = f"Tool events at sequences {seqs} failed hash verification.",
    )
    return rule, contrib


def rule_missing_user_prompt(
    user_prompt:         Optional[str],
    uncertainty_reasons: List[str],
) -> tuple[Optional[TriggeredRule], Optional[RuleContribution]]:
    """R-AMBIG-001: User prompt is absent — authorization cannot be assessed."""
    if user_prompt:
        return None, None
    uncertainty_reasons.append(
        "User prompt is absent or invalid. "
        "Authorization cannot be reliably assessed."
    )
    rule = TriggeredRule(
        rule_id     = "R-AMBIG-001",
        description = "User prompt is absent — authorization cannot be assessed.",
        outcome     = "authorization_unknown",
    )
    contrib = RuleContribution(
        rule_id     = "R-AMBIG-001",
        description = "Missing user prompt",
        delta       = DELTA_MISSING_PROMPT,
        reason      = "Without the user prompt, authorized actions cannot be determined.",
    )
    return rule, contrib


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _ref(session_id: str, entry: object, reason: str) -> EvidenceReference:
    """Build an EvidenceReference from a TimelineEntry."""
    return EvidenceReference(
        session_id           = session_id,
        timeline_sequence    = getattr(entry, "sequence_number", 0),
        raw_sequence_numbers = getattr(entry, "raw_sequence_numbers", []),
        event_type           = getattr(entry, "event_type", ""),
        tool_name            = getattr(entry, "tool_name", None),
        artifact_refs        = getattr(entry, "artifact_refs", []),
        integrity_status     = getattr(entry, "integrity_status", "unknown"),
        reason               = reason,
    )