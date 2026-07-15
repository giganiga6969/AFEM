"""
AFEM Attribution — Confidence Model
=====================================
Transparent, rule-derived confidence scoring for forensic attribution.

The confidence score is bounded to [0.0, 1.0] and is computed as the
sum of all RuleContribution deltas, clamped to the valid range.

This is NOT a statistical probability. It is a forensic confidence score
derived from documented rule contributions. Investigators can read each
RuleContribution to understand why the score is what it is.

Ceiling effects
---------------
Evidence quality imposes a maximum confidence ceiling:
  TRUSTED  + COMPLETE   → no ceiling (full range 0–1)
  DEGRADED or PARTIAL   → ceiling 0.75
  COMPROMISED           → ceiling 0.40
  UNKNOWN               → ceiling 0.30
  FAILED reconstruction → ceiling 0.20

These ceilings are documented constants rather than magic numbers.
"""
from __future__ import annotations

from typing import List

from schemas.attribution import RuleContribution

# ---------------------------------------------------------------------------
# Trust/completeness confidence ceilings
# ---------------------------------------------------------------------------

#: Maximum confidence when evidence trust and reconstruction are fully intact.
CEILING_FULL: float = 1.00

#: Maximum confidence when evidence is degraded or reconstruction is partial.
CEILING_DEGRADED: float = 0.75

#: Maximum confidence when evidence is compromised.
CEILING_COMPROMISED: float = 0.40

#: Maximum confidence when trust is unknown.
CEILING_UNKNOWN: float = 0.30

#: Maximum confidence when reconstruction failed.
CEILING_FAILED: float = 0.20

# ---------------------------------------------------------------------------
# Standard rule delta constants
# ---------------------------------------------------------------------------

DELTA_EXPLICIT_AUTH:         float = +0.35   # User explicitly authorized the action
DELTA_EXACT_MATCH:           float = +0.20   # Observed exactly matches authorized set
#: Explicitly unauthorized observed behavior strongly supports a SCOPE verdict.
#: This is positive because confidence measures certainty in the selected
#: forensic attribution, not whether the observed behavior was desirable.
DELTA_EXPLICIT_SCOPE:        float = +0.35
DELTA_TRUSTED_EVIDENCE:      float = +0.10   # Evidence trust is TRUSTED
DELTA_COMPLETE_RECON:        float = +0.10   # Reconstruction is COMPLETE
DELTA_INTACT_CRITICAL:       float = +0.05   # Critical events have valid integrity
DELTA_INJECTION_MATCH:       float = +0.30   # Injection content matched unauthorized action
DELTA_TEMPORAL_ORDER:        float = +0.10   # Correct temporal ordering confirmed
DELTA_TOOL_CHAIN_CONSISTENT: float = +0.05   # Tool input/output state transitions consistent

DELTA_DEGRADED_TRUST:        float = -0.15   # Evidence trust is DEGRADED
DELTA_PARTIAL_RECON:         float = -0.10   # Reconstruction is PARTIAL
DELTA_MINIMAL_RECON:         float = -0.20   # Reconstruction is MINIMAL
DELTA_INVALID_CRITICAL:      float = -0.20   # A critical event failed hash check
DELTA_MISSING_PROMPT:        float = -0.25   # User prompt is absent
DELTA_MISSING_TOOL_RESULT:   float = -0.10   # A tool result is missing
DELTA_CONTRADICTORY:         float = -0.15   # Contradictory evidence present
DELTA_UNCERTAIN_MAPPING:     float = -0.10   # Action mapping is uncertain
DELTA_AMBIGUOUS_CAUSAL:      float = -0.15   # Causal source cannot be established
DELTA_INJECTION_NO_MATCH:    float = -0.05   # Suspicious content found, no behavioral match


# ---------------------------------------------------------------------------
# Ceiling derivation
# ---------------------------------------------------------------------------


def derive_ceiling(evidence_trust: str, reconstruction_completeness: str) -> float:
    """
    Return the maximum allowed confidence score given evidence quality.

    Parameters
    ----------
    evidence_trust :
        Plain string value of EvidenceTrust (trusted/degraded/compromised/unknown).
    reconstruction_completeness :
        Plain string value of ReconstructionCompleteness (complete/partial/minimal/failed).

    Returns
    -------
    float
        Maximum confidence ceiling in [0.0, 1.0].
    """
    # Failed reconstruction is the strongest downward constraint.
    if reconstruction_completeness == "failed":
        return CEILING_FAILED

    if evidence_trust == "compromised":
        return CEILING_COMPROMISED

    if evidence_trust == "unknown":
        return CEILING_UNKNOWN

    if evidence_trust == "degraded" or reconstruction_completeness in ("partial", "minimal"):
        return CEILING_DEGRADED

    return CEILING_FULL


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------


def compute_score(
    contributions:    List[RuleContribution],
    evidence_trust:   str,
    completeness:     str,
) -> float:
    """
    Compute final confidence score from contributions, capped by ceiling.

    Parameters
    ----------
    contributions :
        All RuleContribution objects accumulated during attribution.
    evidence_trust :
        Plain string value of EvidenceTrust.
    completeness :
        Plain string value of ReconstructionCompleteness.

    Returns
    -------
    float
        Clamped confidence score in [0.0, 1.0].
    """
    raw = sum(c.delta for c in contributions)
    ceiling = derive_ceiling(evidence_trust, completeness)
    return max(0.0, min(ceiling, raw))