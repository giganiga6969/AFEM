"""
AFEM Collector Package
======================

Public interface for the AFEM evidence collection subsystem.

This package is responsible for recording all observable agent activity
as structured forensic events in JSONL format.

Public API
----------
    from collector import EvidenceCollector

The internal implementation lives in ``collector.collector``.
Future phases (Integrity, Attribution, Reconstruction, Reporting)
should import the collector only through this package.
"""

from .collector import EvidenceCollector

__all__ = ["EvidenceCollector"]