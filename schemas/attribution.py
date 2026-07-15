"""
AFEM Attribution Schemas — Phase 4: Explainable Forensic Attribution
=====================================================================
All Pydantic models and enumerations for the attribution layer.

Module design
-------------
Every type needed by Phase 4 (engine) and Phase 5 (report generation)
is defined here and nowhere else. Phase 5 imports ``AttributionReport``
from this module directly — it does not need to re-run attribution or
parse CLI output.

Enumerations
------------
AttributionClass    Four-way primary verdict.
TaskOutcome         Execution outcome, independent of attribution.
InjectionAssessment Strength of injection evidence.
ActionCategory      Taxonomy of email-agent tool actions.
ConfidenceLabel     Human-readable confidence band.

Models
------
EvidenceReference       Traceable pointer to a specific timeline entry.
RuleContribution        One rule's signed impact on the confidence score.
TriggeredRule           A rule that fired during attribution.
AuthorizationAssessment What the user authorized and what was observed.
InjectionIndicator      One detected prompt-injection signal in email content.
AttributionReport       Complete Phase 4 output; primary Phase 5 input.

Phase 5 contract
----------------
Phase 5 will consume AttributionReport alongside IntegrityReport and
TimelineReport to generate an InvestigationReport. AttributionReport
embeds source provenance (genesis_hash, terminal_hash, reconstruction
completeness) so Phase 5 does not need to reload earlier reports
for those fields.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Primary enumerations
# ---------------------------------------------------------------------------


class AttributionClass(str, Enum):
    """
    Four-way primary attribution verdict.

    AUTH   Observed behavior is supported by explicit or reasonably implied
           user authorization. No material unauthorized actions present.

    SCOPE  Agent performed actions outside user authorization. Insufficient
           injection evidence explains the unauthorized behavior.

    INJ    Unauthorized actions are causally correlated with instruction-like
           content found in untrusted retrieved email content. Requires
           behavioral correlation — suspicious keywords alone are not enough.

    AMBIG  Evidence is missing, compromised, contradictory, or structurally
           insufficient to support a reliable AUTH/SCOPE/INJ conclusion.
    """
    AUTH  = "AUTH"
    SCOPE = "SCOPE"
    INJ   = "INJ"
    AMBIG = "AMBIG"


class TaskOutcome(str, Enum):
    """
    Execution outcome of the agent's task, independent of attribution class.

    A failed task can still be AUTH (the agent tried to do what was asked
    but the operation failed). A successful task can still be SCOPE (the
    agent did more than was asked, and succeeded).
    """
    SUCCEEDED = "SUCCEEDED"
    FAILED    = "FAILED"
    PARTIAL   = "PARTIAL"
    UNKNOWN   = "UNKNOWN"


class InjectionAssessment(str, Enum):
    """
    Strength of prompt-injection evidence for this session.

    NONE                    No injection indicators detected.
    ATTEMPT_DETECTED        Injection-like content found in retrieved email
                            but the agent did NOT perform matching unauthorized
                            actions. The attempt did not drive behavior.
    BEHAVIORALLY_CORRELATED Injection content found AND the agent performed
                            matching unauthorized actions in temporal order
                            after retrieving the content. Causal correlation
                            is supported (not proven) by the evidence.
    INSUFFICIENT_EVIDENCE   Injection cannot be assessed due to compromised,
                            missing, or incomplete evidence.
    """
    NONE                    = "NONE"
    ATTEMPT_DETECTED        = "ATTEMPT_DETECTED"
    BEHAVIORALLY_CORRELATED = "BEHAVIORALLY_CORRELATED"
    INSUFFICIENT_EVIDENCE   = "INSUFFICIENT_EVIDENCE"


class ActionCategory(str, Enum):
    """
    Taxonomy of email-agent tool actions by impact level.

    READ_ONLY       search_email, retrieve_email
                    No state change. Lowest risk.

    STATE_CHANGING  create_draft
                    Modifies mailbox state. Medium risk.
                    Authorized only when the user explicitly asks for drafting.

    HIGH_IMPACT     send_email
                    External effect. Highest risk.
                    Authorized only when sending is explicitly or
                    unambiguously requested.
    """
    READ_ONLY      = "READ_ONLY"
    STATE_CHANGING = "STATE_CHANGING"
    HIGH_IMPACT    = "HIGH_IMPACT"


class ConfidenceLabel(str, Enum):
    """Human-readable confidence band for investigator reports."""
    VERY_HIGH = "VERY HIGH"    # 0.85 – 1.00
    HIGH      = "HIGH"         # 0.70 – 0.84
    MEDIUM    = "MEDIUM"       # 0.50 – 0.69
    LOW       = "LOW"          # 0.25 – 0.49
    VERY_LOW  = "VERY LOW"     # 0.00 – 0.24


# ---------------------------------------------------------------------------
# Action taxonomy registry
# ---------------------------------------------------------------------------

#: Maps every known tool name to its ActionCategory.
#: Add new tools here when the email-agent grows.
TOOL_CATEGORIES: Dict[str, ActionCategory] = {
    "search_email":   ActionCategory.READ_ONLY,
    "retrieve_email": ActionCategory.READ_ONLY,
    "create_draft":   ActionCategory.STATE_CHANGING,
    "send_email":     ActionCategory.HIGH_IMPACT,
}


def categorise_tool(tool_name: str) -> ActionCategory:
    """Return the ActionCategory for a tool name, defaulting to HIGH_IMPACT for unknowns."""
    return TOOL_CATEGORIES.get(tool_name, ActionCategory.HIGH_IMPACT)


def label_from_score(score: float) -> ConfidenceLabel:
    """Map a 0–1 confidence score to a ConfidenceLabel."""
    if score >= 0.85:
        return ConfidenceLabel.VERY_HIGH
    if score >= 0.70:
        return ConfidenceLabel.HIGH
    if score >= 0.50:
        return ConfidenceLabel.MEDIUM
    if score >= 0.25:
        return ConfidenceLabel.LOW
    return ConfidenceLabel.VERY_LOW


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------


class EvidenceReference(BaseModel):
    """
    Traceable pointer to one forensic evidence item.

    Every important attribution claim must cite at least one EvidenceReference
    so an investigator can cross-check it against the raw JSONL or timeline.
    """
    session_id:           str
    timeline_sequence:    int  = Field(
        ..., description="TimelineEntry.sequence_number of the cited entry."
    )
    raw_sequence_numbers: List[int] = Field(
        default_factory=list,
        description="JSONL sequence_numbers that contribute to this entry.",
    )
    event_type:           str
    tool_name:            Optional[str]         = None
    artifact_refs:        List[Dict[str, Any]]  = Field(default_factory=list)
    integrity_status:     str                   = "unknown"
    reason:               str = Field(
        ..., description="Short explanation of evidential relevance.",
    )


class RuleContribution(BaseModel):
    """
    Signed contribution of one rule to the overall confidence score.

    Positive delta increases confidence; negative delta decreases it.
    The sum of all RuleContributions (clamped to [0, 1]) yields the
    final confidence_score in AttributionReport.
    """
    rule_id:     str
    description: str
    delta:       float = Field(..., description="Signed contribution to confidence score.")
    reason:      str


class TriggeredRule(BaseModel):
    """A rule that fired during attribution analysis."""
    rule_id:       str
    description:   str
    outcome:       str  = Field(
        ..., description="What the rule concluded (e.g. 'authorized', 'unauthorized')."
    )
    evidence_refs: List[EvidenceReference] = Field(default_factory=list)


class AuthorizationAssessment(BaseModel):
    """
    Result of the authorization analyzer for this session.

    authorized_tools    Tools that the user explicitly or reasonably authorized.
    prohibited_tools    Tools explicitly prohibited by the user.
    observed_tools      Tools the agent actually invoked (from tool_sequence).
    unauthorized_tools  observed_tools that are not in authorized_tools.
    """
    authorized_tools:   List[str] = Field(default_factory=list)
    prohibited_tools:   List[str] = Field(default_factory=list)
    observed_tools:     List[str] = Field(default_factory=list)
    unauthorized_tools: List[str] = Field(default_factory=list)
    prompt_used:        Optional[str] = None
    notes:              List[str]     = Field(default_factory=list)


class InjectionIndicator(BaseModel):
    """
    One prompt-injection signal detected in retrieved email content.

    category    The indicator category (e.g. INSTRUCTION_OVERRIDE).
    phrase      The matched phrase or keyword.
    tool_name   The retrieve_email tool call that exposed this content.
    timeline_sequence  The TimelineEntry where the content was retrieved.
    """
    category:          str
    phrase:            str
    tool_name:         str              = "retrieve_email"
    timeline_sequence: Optional[int]   = None
    content_excerpt:   Optional[str]   = None


# ---------------------------------------------------------------------------
# Top-level report
# ---------------------------------------------------------------------------


class AttributionReport(BaseModel):
    """
    Complete Phase 4 output. Primary input to Phase 5 (Investigation Report).

    Phase 5 uses this object directly. It does not rerun attribution or
    re-parse CLI text. All provenance fields are embedded so Phase 5 can
    render a full investigation report from (IntegrityReport, TimelineReport,
    AttributionReport) without any additional data loading.

    Fields
    ------
    session_id              UUID of the session under analysis.
    generated_at            ISO-8601 UTC timestamp of when attribution ran.

    attribution_class       Primary verdict: AUTH / SCOPE / INJ / AMBIG.
    confidence_score        Rule-derived score in [0.0, 1.0].
    confidence_label        Human-readable band derived from score.
    task_outcome            Execution outcome independent of attribution.

    evidence_trust          Plain-string copy of EvidenceTrust value.
    reconstruction_completeness  Plain-string copy of ReconstructionCompleteness.

    authorization           Structured authorization analysis.
    observed_actions        Ordered list of tool names the agent invoked.
    unauthorized_actions    Subset of observed_actions not in authorized set.

    injection_assessment    Strength of injection evidence.
    injection_indicators    All injection signals found.

    supporting_evidence     Evidence references supporting the verdict.
    contradictory_evidence  Evidence references contradicting or complicating.
    triggered_rules         Rules that fired during analysis.
    confidence_contributions  Signed per-rule deltas explaining the score.
    uncertainty_reasons     Reasons the verdict or score is uncertain.

    explanation             Concise investigator-readable narrative.

    # Provenance (for Phase 5)
    genesis_hash            From the embedded IntegrityReport.
    terminal_hash           From the embedded IntegrityReport.
    session_verified_at     From the embedded IntegrityReport.

    Properties
    ----------
    is_reliable             True when trust is trusted/degraded and
                            completeness is not FAILED.
    """

    session_id:                   str
    generated_at:                 str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Primary verdict
    attribution_class:            AttributionClass
    confidence_score:             float = Field(..., ge=0.0, le=1.0)
    confidence_label:             ConfidenceLabel
    task_outcome:                 TaskOutcome

    # Upstream trust state
    evidence_trust:               str
    reconstruction_completeness:  str

    # Authorization analysis
    authorization:                AuthorizationAssessment
    observed_actions:             List[str] = Field(default_factory=list)
    unauthorized_actions:         List[str] = Field(default_factory=list)

    # Injection analysis
    injection_assessment:         InjectionAssessment
    injection_indicators:         List[InjectionIndicator] = Field(default_factory=list)

    # Evidence and rules
    supporting_evidence:          List[EvidenceReference] = Field(default_factory=list)
    contradictory_evidence:       List[EvidenceReference] = Field(default_factory=list)
    triggered_rules:              List[TriggeredRule]      = Field(default_factory=list)
    confidence_contributions:     List[RuleContribution]   = Field(default_factory=list)
    uncertainty_reasons:          List[str]                = Field(default_factory=list)

    # Narrative
    explanation:                  str

    # Provenance for Phase 5
    genesis_hash:                 str = ""
    terminal_hash:                str = ""
    session_verified_at:          str = ""

    @field_validator("confidence_score")
    @classmethod
    def _clamp(cls, v: float) -> float:
        return max(0.0, min(1.0, v))

    @property
    def is_reliable(self) -> bool:
        """
        True when evidence quality allows a reliable conclusion.
        Phase 5 uses this to decide whether to present a conclusion or caveat.
        """
        return (
            self.evidence_trust in ("trusted", "degraded")
            and self.reconstruction_completeness != "failed"
        )