"""MK1Ai Productization & AegisLab Desktop Integration Package.

Preserves `/テストツール` Phase 1 & Phase 2A files 100% untouched (read-only adapter)
while providing:
- P0/P1: CORE Isolation, ONI_MODE Single Source of Truth, Kill Switch Quorum Gate,
         nftables Hook/Priority/Fragment Verifier, PQC vs QKD & SessionRatchet Audit.
- P2/P3: Honeypot Management Engine (dynamic N-node capacity, Outer/Inner topology,
         OS Image Catalog, 7-step preflight verification, signed backup/restore).
- P4/P5: 4-Tier License & Entitlement Engine, Ed25519 Offline License Engine with
         device binding & monotonic anti-rollback counter, Developer Group Admin.
- P6/P7: Tester Dedicated Streaming Engine (14 states, whitelist canvas, Mock Test Mode
         vs YouTube Live API flow) and full regression test suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add `/テストツール` to sys.path in read-only mode so existing aegislab modules are reused
_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
_TEST_TOOL_DIR = _WORKSPACE_ROOT / "テストツール"
if str(_TEST_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(_TEST_TOOL_DIR))

__all__ = ["_WORKSPACE_ROOT", "_TEST_TOOL_DIR"]
