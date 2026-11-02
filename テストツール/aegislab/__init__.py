"""Project AegisLab — Phase 2A Core Package.

Strictly enforces:
- Initial OFF policy for all 17 user-facing optional features
- Always-ON immutable lock for all 11 mandatory safety controls
- Strict separation between application-level software locks/thresholds
  and OS/kernel/virtualization-level enforcement (marked NOT TESTED in Phase 2A)
- Exact decimal integer handling from 1 to 10^16 (1京) without float rounding
"""

from __future__ import annotations

__version__ = "0.2.0-phase2a"
__phase__ = "PHASE_2A"
