"""Compatibility wrapper for the migrated recon implementation.

The active implementation lives in :mod:`vina.scanners.recon`.
This module re-exports the public recon API so existing imports continue to
work while the package layout is migrated incrementally.
"""

from __future__ import annotations

from ..scanners.recon import ReconModule, ReconResult

__all__ = ["ReconModule", "ReconResult"]
