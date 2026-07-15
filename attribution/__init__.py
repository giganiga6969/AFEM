"""
AFEM Attribution Package — Phase 4: Explainable Forensic Attribution
=====================================================================
Public API re-exports.

Usage:
    from attribution import attribute
    report = attribute(timeline_report)
"""
from __future__ import annotations

from attribution.engine import attribute

__all__ = ["attribute"]