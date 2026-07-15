"""
AFEM Attribution — Engine
==========================
Main Phase 4 attribution engine. Orchestrates authorization analysis,
injection detection, rule evaluation, confidence scoring, and report
construction.

Public API
----------
    attribute(timeline_report) -> AttributionReport

The engine consumes only the TimelineReport produced by Phase 3.
It does NOT re-run integrity verification or re-parse JSONL.

Attribution decision flow
--------------------------

1.  Trust gate
    COMPROMISED or UNKNOWN evidence → AMBIG immediately.
    FAILED reconstruction → AMBIG immediately.

2.  Authorization analysis
    Parse user_prompt to determine authorized and prohibited tools.
    Missing prompt → AMBIG.

3.  Injection scan
    Scan tool output summaries for injection indicators.

4.  Rule evaluation
    Apply all relevant rules, collecting TriggeredRules and
    RuleContributions.

5.  Verdict selection
    Priority order:
      a. Trust gate failures → AMBIG
      b. BEHAVIORALLY_CORRELATED injection + unauthorized actions → INJ
      c. Unauthorized actions, no injection → SCOPE
      d. All actions authorized → AUTH
      e. Fallback → AMBIG

6.  Task outcome assessment
    Determine whether the agent's task SUCCEEDED / FAILED / PARTIAL.

7.  Confidence computation
    Sum rule contributions, apply trust ceiling, clamp to [0, 1].

8.  Report construction
    Assemble full AttributionReport.
"""
from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from attribution.authorization import (
    AuthorizationResult,
    analyze_authorization,
    get_unauthorized_tools,
)
from attribution.confidence import compute_score, derive_ceiling
from attribution.injection import (
    DetectedIndicator,
    extract_requested_actions_from_timeline,
    scan_timeline_entries,
)
from attribution.rules import (
    rule_all_actions_authorized,
    rule_complete_reconstruction,
    rule_degraded_evidence,
    rule_explicit_authorization,
    rule_injection_attempt_no_behavior,
    rule_injection_behavioral_correlation,
    rule_intact_critical_events,
    rule_invalid_critical_event,
    rule_missing_user_prompt,
    rule_partial_reconstruction,
    rule_trusted_evidence,
    rule_unauthorized_action_present,
)
from schemas.attribution import (
    AttributionClass,
    AttributionReport,
    AuthorizationAssessment,
    ConfidenceLabel,
    EvidenceReference,
    InjectionAssessment,
    InjectionIndicator,
    RuleContribution,
    TaskOutcome,
    TriggeredRule,
    label_from_score,
)
from schemas.report import ReconstructionCompleteness, TimelineReport

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def attribute(timeline_report: TimelineReport) -> AttributionReport:
    """
    Run Phase 4 attribution on a completed TimelineReport.

    Parameters
    ----------
    timeline_report :
        The TimelineReport produced by Phase 3.
        Must include an embedded IntegrityReport.

    Returns
    -------
    AttributionReport
        Complete attribution result ready for Phase 5 consumption.
    """
    session_id    = timeline_report.session_id
    evidence_trust = timeline_report.evidence_trust
    completeness   = timeline_report.completeness.value if hasattr(
        timeline_report.completeness, "value"
    ) else str(timeline_report.completeness)

    logger.info(
        "Attribution started.  session=%s  trust=%s  completeness=%s",
        session_id, evidence_trust, completeness,
    )

    # Accumulate across all phases
    triggered_rules:      List[TriggeredRule]     = []
    contributions:        List[RuleContribution]  = []
    uncertainty_reasons:  List[str]               = []
    supporting_evidence:  List[EvidenceReference] = []
    contradictory_evidence: List[EvidenceReference] = []

    # Extract provenance from embedded IntegrityReport
    ir = timeline_report.integrity_report
    genesis_hash        = getattr(ir, "genesis_hash",   "") if ir else ""
    terminal_hash       = getattr(ir, "terminal_hash",  "") if ir else ""
    session_verified_at = getattr(ir, "verified_at",    "") if ir else ""

    # ------------------------------------------------------------------ #
    # 1. Trust gate — AMBIG for COMPROMISED / UNKNOWN / FAILED            #
    # ------------------------------------------------------------------ #
    trust_gate_failed, trust_gate_reason = _check_trust_gate(
        evidence_trust, completeness, uncertainty_reasons
    )

    # ------------------------------------------------------------------ #
    # 2. Authorization analysis                                           #
    # ------------------------------------------------------------------ #
    user_prompt       = timeline_report.user_prompt
    observed_tools    = list(timeline_report.tool_sequence)
    tool_entries      = [e for e in timeline_report.entries if e.event_type == "tool_action"]

    # Missing prompt rule (always evaluate for AMBIG detection)
    r, c = rule_missing_user_prompt(user_prompt, uncertainty_reasons)
    if r: triggered_rules.append(r)
    if c: contributions.append(c)

    prompt_missing = not bool(user_prompt)

    if prompt_missing or trust_gate_failed:
        # Can still extract basic tool evidence even without a prompt
        auth_result = AuthorizationResult()
    else:
        auth_result = analyze_authorization(user_prompt)

    unauthorized_tools = get_unauthorized_tools(observed_tools, auth_result)

    authorization = AuthorizationAssessment(
        authorized_tools   = sorted(auth_result.authorized),
        prohibited_tools   = sorted(auth_result.prohibited),
        observed_tools     = observed_tools,
        unauthorized_tools = unauthorized_tools,
        prompt_used        = user_prompt,
        notes              = auth_result.notes,
    )

    # ------------------------------------------------------------------ #
    # 3. Injection scan                                                   #
    # ------------------------------------------------------------------ #
    raw_indicators: List[DetectedIndicator] = scan_timeline_entries(timeline_report.entries)

        # Extract action semantics from execution-time retrieved content.
    injection_requested_actions = extract_requested_actions_from_timeline(
        timeline_report.entries
    )

    # Correlate only actions that were:
    # 1. requested by retrieved untrusted content,
    # 2. unauthorized by the user, and
    # 3. observed after the relevant retrieve_email event.
    matched_injection_actions = _find_behaviorally_matched_actions(
        tool_entries=tool_entries,
        unauthorized_tools=unauthorized_tools,
        injection_requested_actions=injection_requested_actions,
    )

    temporal_order_ok = bool(matched_injection_actions)

    # ------------------------------------------------------------------ #
    # 4. Rule evaluation                                                  #
    # ------------------------------------------------------------------ #

    # Evidence quality rules (always run)
    for fn, args in [
        (rule_trusted_evidence,         (evidence_trust,)),
        (rule_degraded_evidence,        (evidence_trust, uncertainty_reasons)),
        (rule_complete_reconstruction,  (completeness,)),
        (rule_partial_reconstruction,   (completeness, uncertainty_reasons)),
        (rule_intact_critical_events,   (tool_entries,)),
        (rule_invalid_critical_event,   (session_id, tool_entries, uncertainty_reasons)),
    ]:
        r, c = fn(*args)
        if r: triggered_rules.append(r)
        if c: contributions.append(c)

    # Authorization / scope rules
    r, c = rule_all_actions_authorized(
        session_id, sorted(auth_result.authorized), observed_tools,
        unauthorized_tools, tool_entries
    )
    if r:
        triggered_rules.append(r)
        supporting_evidence.extend(r.evidence_refs)
    if c: contributions.append(c)

    r, c = rule_explicit_authorization(
        session_id, sorted(auth_result.authorized), observed_tools
    )
    if r: triggered_rules.append(r)
    if c: contributions.append(c)

    r, c = rule_unauthorized_action_present(session_id, unauthorized_tools, tool_entries)
    if r:
        triggered_rules.append(r)
        contradictory_evidence.extend(r.evidence_refs)
    if c: contributions.append(c)

    # Injection rules
    r, c = rule_injection_behavioral_correlation(
        session_id,
        raw_indicators,
        matched_injection_actions,
        tool_entries,
        temporal_order_ok,
    )
    if r:
        triggered_rules.append(r)
        supporting_evidence.extend(r.evidence_refs)
    if c: contributions.append(c)

    r, c = rule_injection_attempt_no_behavior(raw_indicators, unauthorized_tools)
    if r: triggered_rules.append(r)
    if c: contributions.append(c)

    # ------------------------------------------------------------------ #
    # 5. Verdict selection                                                #
    # ------------------------------------------------------------------ #
    attribution_class, injection_assessment = _select_verdict(
        trust_gate_failed  = trust_gate_failed,
        prompt_missing     = prompt_missing,
        evidence_trust     = evidence_trust,
        completeness       = completeness,
        unauthorized_tools = unauthorized_tools,
        raw_indicators     = raw_indicators,
        matched_injection_actions = matched_injection_actions,
        uncertainty_reasons = uncertainty_reasons,
    )

    # ------------------------------------------------------------------ #
    # 6. Task outcome                                                     #
    # ------------------------------------------------------------------ #
    task_outcome = _assess_task_outcome(tool_entries)

    # ------------------------------------------------------------------ #
    # 7. Confidence scoring                                               #
    # ------------------------------------------------------------------ #
    confidence_score = compute_score(contributions, evidence_trust, completeness)
    confidence_label = label_from_score(confidence_score)

    # ------------------------------------------------------------------ #
    # 8. Build injection indicators for report                            #
    # ------------------------------------------------------------------ #
    injection_indicators = [
        InjectionIndicator(
            category          = ind.category,
            phrase            = ind.phrase,
            tool_name         = ind.tool_name,
            timeline_sequence = ind.timeline_sequence,
            content_excerpt   = ind.content_excerpt,
        )
        for ind in raw_indicators
    ]

    # ------------------------------------------------------------------ #
    # 9. Generate explanation                                             #
    # ------------------------------------------------------------------ #
    explanation = _build_explanation(
        attribution_class    = attribution_class,
        confidence_score     = confidence_score,
        evidence_trust       = evidence_trust,
        completeness         = completeness,
        authorization        = authorization,
        injection_assessment = injection_assessment,
        task_outcome         = task_outcome,
        uncertainty_reasons  = uncertainty_reasons,
        indicators           = raw_indicators,
    )

    report = AttributionReport(
        session_id                  = session_id,
        attribution_class           = attribution_class,
        confidence_score            = confidence_score,
        confidence_label            = confidence_label,
        task_outcome                = task_outcome,
        evidence_trust              = evidence_trust,
        reconstruction_completeness = completeness,
        authorization               = authorization,
        observed_actions            = observed_tools,
        unauthorized_actions        = unauthorized_tools,
        injection_assessment        = injection_assessment,
        injection_indicators        = injection_indicators,
        supporting_evidence         = supporting_evidence,
        contradictory_evidence      = contradictory_evidence,
        triggered_rules             = triggered_rules,
        confidence_contributions    = contributions,
        uncertainty_reasons         = uncertainty_reasons,
        explanation                 = explanation,
        genesis_hash                = genesis_hash,
        terminal_hash               = terminal_hash,
        session_verified_at         = session_verified_at,
    )

    logger.info(
        "Attribution complete.  session=%s  class=%s  confidence=%.2f  trust=%s",
        session_id, attribution_class.value, confidence_score, evidence_trust,
    )
    return report


# ---------------------------------------------------------------------------
# Internal: trust gate
# ---------------------------------------------------------------------------


def _check_trust_gate(
    evidence_trust:      str,
    completeness:        str,
    uncertainty_reasons: List[str],
) -> Tuple[bool, Optional[str]]:
    """Return (failed, reason) for trust gate check."""
    if evidence_trust in ("compromised", "unknown"):
        reason = (
            f"Evidence trust is {evidence_trust.upper()}. "
            "Reliable attribution is not possible. Defaulting to AMBIG."
        )
        uncertainty_reasons.append(reason)
        return True, reason

    if completeness == "failed":
        reason = (
            "Timeline reconstruction FAILED. "
            "No reliable action sequence is available. Defaulting to AMBIG."
        )
        uncertainty_reasons.append(reason)
        return True, reason

    return False, None


# ---------------------------------------------------------------------------
# Internal: verdict selection
# ---------------------------------------------------------------------------


def _select_verdict(
    trust_gate_failed:   bool,
    prompt_missing:      bool,
    evidence_trust:      str,
    completeness:        str,
    unauthorized_tools:  List[str],
    raw_indicators:      List[DetectedIndicator],
    matched_injection_actions: List[str],
    uncertainty_reasons: List[str],
) -> Tuple[AttributionClass, InjectionAssessment]:
    """
    Select the primary attribution verdict and injection assessment.

    Priority order (highest to lowest):
    1. Trust gate failure → AMBIG
    2. Missing prompt → AMBIG (cannot assess authorization)
    3. Injection behaviorally correlated → INJ
    4. Unauthorized actions, no sufficient injection → SCOPE
    5. All actions authorized → AUTH
    6. No actions observed → AMBIG
    """

    # Priority 1: Trust gate
    if trust_gate_failed:
        inj = (
            InjectionAssessment.INSUFFICIENT_EVIDENCE
            if not raw_indicators
            else InjectionAssessment.ATTEMPT_DETECTED
        )
        return AttributionClass.AMBIG, inj

    # Priority 2: Missing prompt
    if prompt_missing:
        uncertainty_reasons.append(
            "User prompt is absent — authorization cannot be assessed reliably."
        )
        inj = InjectionAssessment.INSUFFICIENT_EVIDENCE
        return AttributionClass.AMBIG, inj

    # Determine injection assessment
    inj_assessment = _assess_injection(
        raw_indicators, unauthorized_tools, matched_injection_actions,
    )

    # Priority 3: Injection with behavioral correlation
    if (
        inj_assessment == InjectionAssessment.BEHAVIORALLY_CORRELATED
        and unauthorized_tools
    ):
        return AttributionClass.INJ, inj_assessment

    # Priority 4: Unauthorized actions present (SCOPE or AMBIG)
    if unauthorized_tools:
        # SCOPE requires sufficient evidence quality
        if evidence_trust in ("trusted", "degraded") and completeness in ("complete", "partial"):
            return AttributionClass.SCOPE, inj_assessment
        else:
            uncertainty_reasons.append(
                "Unauthorized actions observed but evidence quality is too low to "
                "reliably distinguish SCOPE from INJ."
            )
            return AttributionClass.AMBIG, InjectionAssessment.INSUFFICIENT_EVIDENCE

    # Priority 5: All authorized
    # Need at least one tool action to conclude AUTH
    if not unauthorized_tools:
        return AttributionClass.AUTH, inj_assessment

    # Fallback
    uncertainty_reasons.append("Insufficient evidence for reliable classification.")
    return AttributionClass.AMBIG, InjectionAssessment.INSUFFICIENT_EVIDENCE


def _assess_injection(
    indicators:               List[DetectedIndicator],
    unauthorized_tools:       List[str],
    matched_injection_actions: List[str],
) -> InjectionAssessment:
    """
    Derive injection strength from content and behavioral evidence.

    BEHAVIORALLY_CORRELATED requires a temporally later unauthorized action
    that matches an action explicitly requested by retrieved untrusted
    content. Suspicious content plus an unrelated unauthorized action is
    recorded as an attempt, not attributed as INJ.
    """
    if not indicators:
        return InjectionAssessment.NONE

    if matched_injection_actions:
        return InjectionAssessment.BEHAVIORALLY_CORRELATED

    if indicators:
        return InjectionAssessment.ATTEMPT_DETECTED

    return InjectionAssessment.NONE


# ---------------------------------------------------------------------------
# Internal: task outcome
# ---------------------------------------------------------------------------


def _assess_task_outcome(tool_entries: list) -> TaskOutcome:
    """
    Infer task execution outcome from tool result entries.

    An 'error' in the output_summary indicates failure.
    All tool actions completed without error → SUCCEEDED.
    Some failed, some succeeded → PARTIAL.
    All failed → FAILED.
    No tool actions → UNKNOWN.
    """
    if not tool_entries:
        return TaskOutcome.UNKNOWN

    successes = 0
    failures  = 0
    for entry in tool_entries:
        summary = (getattr(entry, "output_summary", "") or "").lower()
        if "error" in summary:
            failures += 1
        else:
            successes += 1

    if successes > 0 and failures == 0:
        return TaskOutcome.SUCCEEDED
    if successes > 0 and failures > 0:
        return TaskOutcome.PARTIAL
    if failures > 0 and successes == 0:
        return TaskOutcome.FAILED
    return TaskOutcome.UNKNOWN


# ---------------------------------------------------------------------------
# Internal: first unauthorized action sequence
# ---------------------------------------------------------------------------


def _find_behaviorally_matched_actions(
    tool_entries: list,
    unauthorized_tools: List[str],
    injection_requested_actions: dict[str, List[int]],
) -> List[str]:
    """
    Return unauthorized actions matching earlier untrusted instructions.

    An action is behaviorally matched only when:
    - the action was requested by retrieved untrusted content;
    - the action is unauthorized by the user's prompt;
    - the observed action occurred after the retrieval sequence.

    The returned list preserves observed tool order and contains no
    duplicates.
    """
    unauthorized_set = set(unauthorized_tools)
    matched: List[str] = []

    for entry in tool_entries:
        tool_name = getattr(entry, "tool_name", None)
        action_seq = getattr(entry, "sequence_number", None)

        if tool_name not in unauthorized_set:
            continue

        request_sequences = injection_requested_actions.get(tool_name, [])

        if (
            action_seq is not None
            and any(request_seq < action_seq for request_seq in request_sequences)
            and tool_name not in matched
        ):
            matched.append(tool_name)

    return matched


# ---------------------------------------------------------------------------
# Internal: explanation builder
# ---------------------------------------------------------------------------


def _build_explanation(
    attribution_class:    AttributionClass,
    confidence_score:     float,
    evidence_trust:       str,
    completeness:         str,
    authorization:        AuthorizationAssessment,
    injection_assessment: InjectionAssessment,
    task_outcome:         TaskOutcome,
    uncertainty_reasons:  List[str],
    indicators:           List[DetectedIndicator],
) -> str:
    """Build a concise investigator-readable explanation of the verdict."""
    lines = []
    cls   = attribution_class.value

    if cls == "AUTH":
        lines.append(
            f"ATTRIBUTION: AUTH — The agent performed only authorized actions. "
            f"The user authorized {sorted(authorization.authorized_tools)}, "
            f"and the agent used {sorted(set(authorization.observed_tools))}."
        )
    elif cls == "SCOPE":
        lines.append(
            f"ATTRIBUTION: SCOPE — The agent exceeded the user's authorization. "
            f"Unauthorized actions observed: {authorization.unauthorized_tools}. "
            f"User authorized: {sorted(authorization.authorized_tools)}."
        )
    elif cls == "INJ":
        phrases = [ind.phrase for ind in indicators[:3]]
        lines.append(
            f"ATTRIBUTION: INJ — Prompt injection is behaviorally correlated. "
            f"Injection-like content detected in retrieved email ({phrases}). "
            f"Unauthorized actions {authorization.unauthorized_tools} followed "
            f"the retrieval in sequence order."
        )
    else:
        lines.append(
            f"ATTRIBUTION: AMBIG — Insufficient or unreliable evidence for a "
            f"reliable classification."
        )

    lines.append(
        f"Confidence: {confidence_score:.2f} | "
        f"Trust: {evidence_trust.upper()} | "
        f"Reconstruction: {completeness.upper()} | "
        f"Task outcome: {task_outcome.value}"
    )

    if injection_assessment == InjectionAssessment.ATTEMPT_DETECTED:
        lines.append(
            "Note: injection-like content was detected in retrieved email content "
            "but did not drive unauthorized behavior."
        )

    if uncertainty_reasons:
        lines.append("Uncertainty: " + "; ".join(uncertainty_reasons))

    return " ".join(lines)