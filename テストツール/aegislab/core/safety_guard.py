"""Application-level Resource Threshold Guard & Phase 2A Prohibited Action Gate (Module 4).

IMPORTANT DISTINCTION:
- This module implements APPLICATION_THRESHOLD_GUARD and APPLICATION_CONFIG_LOCK
  inside the Python process.
- OS/kernel/hypervisor-level enforcement (cgroups v2, namespaces, VM isolation,
  kernel network filtering) is NOT executed in Phase 2A and is reported as NOT TESTED.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from aegislab.core.value_types import ControlScope, Verdict


class ResourceLimitExceededError(RuntimeError):
    """Raised when an application-level memory or disk safety threshold is breached."""


class ProhibitedPhase2AOperationError(PermissionError):
    """Raised when an operation prohibited in Phase 2A is invoked."""


@dataclass(frozen=True)
class ResourceThresholds:
    """Application-level safety thresholds (always active even when UI panel is OFF)."""

    min_host_available_ram_mib: int = 180
    max_process_rss_mib: int = 250
    min_disk_free_mib: int = 600


@dataclass(frozen=True)
class ThresholdCheckReceipt:
    """Audit receipt explicitly distinguishing application check vs OS enforcement."""

    passed: bool
    control_scope: ControlScope
    os_enforcement_status: Verdict
    host_available_ram_mib: int
    process_rss_mib: int
    disk_free_mib: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "control_scope": self.control_scope.value,
            "os_enforcement_status": self.os_enforcement_status.value,
            "host_available_ram_mib": self.host_available_ram_mib,
            "process_rss_mib": self.process_rss_mib,
            "disk_free_mib": self.disk_free_mib,
            "reason": self.reason,
        }


class SafetyGuard:
    """Always-active application-level safety guard."""

    PROHIBITED_OPERATIONS_PHASE2A: dict[str, str] = {
        "os_image_build": "OS image build is prohibited in Phase 2A (NOT TESTED)",
        "vm_launch": "VM / microVM launch is prohibited in Phase 2A (NOT TESTED)",
        "namespace_or_veth_mutation": "Namespace / veth / network changes are prohibited in Phase 2A (NOT TESTED)",
        "real_packet_transmission": "Real network packet transmission is prohibited in Phase 2A (NOT TESTED)",
        "xdp_ebpf_load": "XDP/eBPF compilation, loading, and attachment are prohibited in Phase 2A (NOT TESTED)",
        "screen_capture": "Screen capture is prohibited in Phase 2A (NOT TESTED)",
        "microphone_capture": "Microphone / audio capture is prohibited in Phase 2A (NOT TESTED)",
        "recording_start": "Local video/audio recording is prohibited in Phase 2A (NOT TESTED)",
        "live_streaming_start": "Live streaming connection and transmission are prohibited in Phase 2A (NOT TESTED)",
        "external_api_call": "External API calls are prohibited in Phase 2A (NOT TESTED)",
    }

    def __init__(
        self,
        workspace_dir: Path,
        thresholds: ResourceThresholds | None = None,
    ) -> None:
        self._workspace_dir = workspace_dir
        self._thresholds = thresholds or ResourceThresholds()

    @property
    def thresholds(self) -> ResourceThresholds:
        return self._thresholds

    @staticmethod
    def read_host_available_ram_mib() -> int:
        meminfo = Path("/proc/meminfo")
        if not meminfo.is_file():
            return 0
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1]) // 1024
        return 0

    @staticmethod
    def read_process_rss_mib() -> int:
        status_path = Path("/proc/self/status")
        if not status_path.is_file():
            return 0
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1]) // 1024
        return 0

    def read_disk_free_mib(self) -> int:
        st = os.statvfs(self._workspace_dir)
        return (st.f_bavail * st.f_frsize) // (1024 * 1024)

    def check_resource_limits(
        self,
        *,
        simulated_available_ram_mib: int | None = None,
        simulated_process_rss_mib: int | None = None,
        simulated_disk_free_mib: int | None = None,
    ) -> ThresholdCheckReceipt:
        """Verify application-level resource thresholds (always active)."""
        avail_ram = (
            simulated_available_ram_mib
            if simulated_available_ram_mib is not None
            else self.read_host_available_ram_mib()
        )
        proc_rss = (
            simulated_process_rss_mib
            if simulated_process_rss_mib is not None
            else self.read_process_rss_mib()
        )
        disk_free = (
            simulated_disk_free_mib
            if simulated_disk_free_mib is not None
            else self.read_disk_free_mib()
        )

        violations: list[str] = []
        if avail_ram < self._thresholds.min_host_available_ram_mib:
            violations.append(
                f"Host available RAM ({avail_ram} MiB) < minimum threshold ({self._thresholds.min_host_available_ram_mib} MiB)"
            )
        if proc_rss > self._thresholds.max_process_rss_mib:
            violations.append(
                f"Process RSS ({proc_rss} MiB) > maximum threshold ({self._thresholds.max_process_rss_mib} MiB)"
            )
        if disk_free < self._thresholds.min_disk_free_mib:
            violations.append(
                f"Disk free ({disk_free} MiB) < minimum threshold ({self._thresholds.min_disk_free_mib} MiB)"
            )

        if violations:
            reason = "; ".join(violations)
            raise ResourceLimitExceededError(
                f"[APPLICATION_THRESHOLD_GUARD] Safety halt triggered: {reason}"
            )

        return ThresholdCheckReceipt(
            passed=True,
            control_scope=ControlScope.APPLICATION_THRESHOLD_GUARD,
            os_enforcement_status=Verdict.NOT_TESTED,
            host_available_ram_mib=avail_ram,
            process_rss_mib=proc_rss,
            disk_free_mib=disk_free,
            reason=(
                "Application-level threshold check passed. "
                "OS/kernel resource quota enforcement is NOT TESTED in Phase 2A."
            ),
        )

    def guard_prohibited_operation(self, operation_key: str) -> None:
        """Block any operation prohibited in Phase 2A."""
        reason = self.PROHIBITED_OPERATIONS_PHASE2A.get(
            operation_key,
            f"Operation '{operation_key}' is prohibited in Phase 2A (NOT TESTED)",
        )
        raise ProhibitedPhase2AOperationError(reason)
