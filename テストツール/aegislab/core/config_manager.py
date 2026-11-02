"""Configuration & Feature Switch Manager (Module 21).

Enforces:
- All 17 user-facing optional features default to OFF (False).
- Orthogonal toggling: enabling one optional feature never enables another.
- Phase 2A prohibited features cannot be enabled without explicit phase unlock.
- All 11 mandatory safety controls are permanently ON (True) in application config
  and cannot be disabled via API or config reload.
- Clear distinction between APPLICATION_CONFIG_LOCK (verified in software)
  and OS_VIRTUALIZATION_ISOLATION (NOT TESTED in Phase 2A).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegislab.core.value_types import ControlScope, Verdict


class ImmutableSafetyPolicyError(PermissionError):
    """Raised when attempting to disable a mandatory safety mechanism."""


class Phase2AProhibitedFeatureError(PermissionError):
    """Raised when attempting to activate an operation prohibited in Phase 2A."""


OPTIONAL_FEATURES: tuple[str, ...] = (
    "auto_packet_simulation",
    "auto_virtual_bot_start",
    "real_packet_transmission",
    "load_testing",
    "external_network_communication",
    "xdp_ebpf_execution_test",
    "device_monitoring_panel",
    "battery_power_monitoring_panel",
    "auto_resource_control",
    "overlay_display",
    "scene_auto_switching",
    "screen_capture",
    "microphone_input",
    "desktop_audio_input",
    "recording",
    "live_streaming",
    "external_api_integration",
    "adaptive_packet_control",
    "tts_auto_narration",
    "audio_mixer_control",
)

# Features that are strictly prohibited from activation during Phase 2A
PHASE2A_LOCKED_FEATURES: frozenset[str] = frozenset(
    {
        "real_packet_transmission",
        "load_testing",
        "external_network_communication",
        "xdp_ebpf_execution_test",
        "screen_capture",
        "microphone_input",
        "desktop_audio_input",
        "recording",
        "live_streaming",
        "external_api_integration",
    }
)

# Features that must ALWAYS reset to False on restart / reload
RESET_ON_RESTART_FEATURES: frozenset[str] = frozenset(OPTIONAL_FEATURES)

MANDATORY_SAFETY_CONTROLS: tuple[str, ...] = (
    "prevent_host_direct_untrusted_exec",
    "virtual_environment_isolation_policy",
    "mandatory_resource_limits",
    "block_unapproved_external_tx",
    "strict_input_validation",
    "secret_and_pii_protection",
    "separate_real_and_simulated_metrics",
    "require_explicit_prestream_approval",
    "quarantine_unverified_os_images",
    "halt_on_isolation_or_integrity_breach",
    "immutable_audit_logging",
)


@dataclass(frozen=True)
class SecurityControlStatus:
    """Separates software switch status from OS/kernel enforcement status."""

    control_name: str
    software_switch_locked_on: bool
    software_scope: ControlScope
    os_kernel_enforcement_status: Verdict
    os_scope: ControlScope
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_name": self.control_name,
            "software_switch_locked_on": self.software_switch_locked_on,
            "software_scope": self.software_scope.value,
            "os_kernel_enforcement_status": self.os_kernel_enforcement_status.value,
            "os_scope": self.os_scope.value,
            "note": self.note,
        }


class ConfigManager:
    """Manages optional feature switches and immutable safety controls."""

    def __init__(self, *, enforce_phase2a_locks: bool = True) -> None:
        self._enforce_phase2a_locks = enforce_phase2a_locks
        self._optional_state: dict[str, bool] = {
            name: False for name in OPTIONAL_FEATURES
        }
        self._mandatory_state: dict[str, bool] = {
            name: True for name in MANDATORY_SAFETY_CONTROLS
        }
        self._default_guest_os: str = "mk1ai-secure-linux"
        self._default_guest_os_status: str = "NOT_BUILT_UNVERIFIED"

    @property
    def default_guest_os(self) -> str:
        return self._default_guest_os

    @property
    def default_guest_os_status(self) -> str:
        return self._default_guest_os_status

    def get_optional_feature(self, feature_name: str) -> bool:
        if feature_name not in self._optional_state:
            raise KeyError(f"Unknown optional feature: {feature_name}")
        return self._optional_state[feature_name]

    def get_all_optional_features(self) -> dict[str, bool]:
        return dict(self._optional_state)

    def get_all_mandatory_controls(self) -> dict[str, bool]:
        return dict(self._mandatory_state)

    def get_detailed_mandatory_control_statuses(
        self,
    ) -> list[SecurityControlStatus]:
        """Return mandatory controls with explicit software vs OS scope separation."""
        statuses: list[SecurityControlStatus] = []
        for name in MANDATORY_SAFETY_CONTROLS:
            statuses.append(
                SecurityControlStatus(
                    control_name=name,
                    software_switch_locked_on=self._mandatory_state[name],
                    software_scope=ControlScope.APPLICATION_CONFIG_LOCK,
                    os_kernel_enforcement_status=Verdict.NOT_TESTED,
                    os_scope=ControlScope.OS_VIRTUALIZATION_ISOLATION,
                    note=(
                        "Software policy lock is active (APPLICATION_CONFIG_LOCK). "
                        "OS/hypervisor-level isolation is NOT TESTED in Phase 2A."
                    ),
                )
            )
        return statuses

    def set_optional_feature(self, feature_name: str, enabled: bool) -> None:
        """Set a single optional feature without affecting any other feature."""
        if not isinstance(enabled, bool):
            raise TypeError("Feature switch value must be a boolean")
        if feature_name in self._mandatory_state:
            raise ImmutableSafetyPolicyError(
                f"Mandatory safety control '{feature_name}' cannot be modified via optional feature API"
            )
        if feature_name not in self._optional_state:
            raise KeyError(f"Unknown optional feature: {feature_name}")

        if enabled and self._enforce_phase2a_locks and feature_name in PHASE2A_LOCKED_FEATURES:
            raise Phase2AProhibitedFeatureError(
                f"Feature '{feature_name}' is prohibited in Phase 2A and remains OFF (NOT TESTED)"
            )
        self._optional_state[feature_name] = enabled

    def set_mandatory_control(self, control_name: str, enabled: bool) -> None:
        """Mandatory safety controls cannot be turned off."""
        if control_name not in self._mandatory_state:
            raise KeyError(f"Unknown mandatory safety control: {control_name}")
        if not enabled:
            raise ImmutableSafetyPolicyError(
                f"Mandatory safety control '{control_name}' is permanently locked ON and cannot be disabled"
            )

    def load_persisted_dict(self, raw_config: dict[str, Any]) -> None:
        """Load persisted config while enforcing mandatory safety and restart resets."""
        if not isinstance(raw_config, dict):
            raise ValueError("Configuration payload must be a dict")

        mandatory_section = raw_config.get("mandatory_controls", {})
        if not isinstance(mandatory_section, dict):
            raise ValueError("mandatory_controls must be a dict")
        for key, val in mandatory_section.items():
            if key not in self._mandatory_state:
                raise KeyError(f"Unknown mandatory control in config: {key}")
            if val is not True:
                raise ImmutableSafetyPolicyError(
                    f"Config integrity violation: mandatory control '{key}' cannot be set to {val!r}"
                )

        # On restart / reload, all user-facing optional features reset to OFF
        for name in OPTIONAL_FEATURES:
            self._optional_state[name] = False

    def simulate_restart(self) -> None:
        """Reset all dangerous and optional switches to OFF upon restart."""
        for name in RESET_ON_RESTART_FEATURES:
            self._optional_state[name] = False
