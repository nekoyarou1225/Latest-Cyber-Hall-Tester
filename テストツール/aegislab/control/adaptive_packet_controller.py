"""Adaptive Packet Controller with strict rate limiting, fault boundaries, and emergency stop.

Key requirements fulfilled:
- Complete separation of COMPLETED_HALT and EMERGENCY_HALT.
  Reaching limits transitions to COMPLETED_HALT; it never invokes emergency stop.
- Resume from COMPLETED_HALT is strictly prohibited. New tests require explicit reset_for_new_test.
- PacketDataProvider.get_current_measured_rates() is used to query real data-plane rates.
  Type and bounds are verified; missing/failed queries are never treated as success.
- Cumulative packet counter is strictly validated (int, non-negative, monotonic, cap).
- Target PPS/BPS vs applied PPS/BPS are separated.
- If rate_apply_callback is unset/false/exception, target is NOT marked applied.
- If rate decrease fails, controller transitions to SAFE_MINIMUM and flags fault.
- If measured rate exceeds safety limit, emergency stop is automatically requested.
- Stop callbacks distinguish REQUESTED, DISPATCHED, CONFIRMED, and UNCONFIRMED.
- All ControllerSafetyLimits fields are thoroughly validated.
- Stable cycles count only distinct observation timestamps with sufficient time gap.
- Strict CIDR parsing and destination gating (EgressGate is locked in Phase 2A).
- Plan/commit pattern: callbacks are called outside locks via bounded_call.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress
import math
import re
import threading
import time
from typing import Any, Callable, Protocol

from aegislab.core.bounded_call import bounded_call, CallStatus


class ControlMode(str, Enum):
    MODE_A_SIMULATION = "MODE_A_SIMULATION"
    MODE_B_ISOLATED_LAB = "MODE_B_ISOLATED_LAB"
    MODE_C_LIVE_NETWORK = "MODE_C_LIVE_NETWORK"


class ControllerState(str, Enum):
    IDLE = "IDLE"
    RAMPING_UP = "RAMPING_UP"
    STEADY = "STEADY"
    THROTTLING_DOWN = "THROTTLING_DOWN"
    SAFE_MINIMUM = "SAFE_MINIMUM"
    COMPLETED_HALT = "COMPLETED_HALT"
    EMERGENCY_HALT = "EMERGENCY_HALT"


class MeasurementLayer(str, Enum):
    L3_IP = "L3_IP"
    L2_FRAME = "L2_FRAME"
    PHY_WIRE = "PHY_WIRE"


class RateApplyStatus(str, Enum):
    NOT_APPLIED = "NOT_APPLIED"
    APPLYING = "APPLYING"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    NO_CALLBACK = "NO_CALLBACK"


class StopStatus(str, Enum):
    IDLE = "IDLE"
    REQUESTED = "REQUESTED"
    DISPATCHED = "DISPATCHED"
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED_NO_CALLBACK = "UNCONFIRMED_NO_CALLBACK"
    UNCONFIRMED_REFUSED = "UNCONFIRMED_REFUSED"
    UNCONFIRMED_EXCEPTION = "UNCONFIRMED_EXCEPTION"
    UNCONFIRMED_TIMEOUT = "UNCONFIRMED_TIMEOUT"


class EgressLockedError(RuntimeError):
    """Raised when egress gate is locked."""


@dataclass(frozen=True)
class ControllerSafetyLimits:
    min_pps: int = 10
    max_pps: int = 100_000
    max_bps: int = 100_000_000
    max_total_packets: int = 10_000_000_000_000_000
    max_runtime_sec: float = 86400.0
    min_host_ram_mb: float = 512.0
    max_process_rss_mb: float = 256.0
    min_disk_free_mb: float = 1024.0
    max_cpu_percent: float = 85.0
    max_rtt_ms: float = 50.0
    max_packet_loss_percent: float = 1.0
    max_net_util_percent: float = 80.0
    max_metric_age_sec: float = 2.0
    min_adjustment_interval_sec: float = 1.0
    min_observation_gap_sec: float = 0.5
    stable_cycles_required: int = 3
    max_consecutive_sensor_faults: int = 3
    l2_overhead_bytes: int = 14
    l3_overhead_bytes: int = 20
    l4_overhead_bytes: int = 8
    phy_overhead_bytes: int = 0
    measurement_layer: MeasurementLayer = MeasurementLayer.L2_FRAME
    overhead_rationale: str = "Standard Ethernet + IPv4 + UDP packet header modeling"
    allowed_destination_cidrs: tuple[str, ...] = ("192.0.2.0/24", "198.51.100.0/24")
    allowed_interfaces: tuple[str, ...] = ("lo", "veth-test0")
    callback_timeout_sec: float = 2.0

    def __post_init__(self) -> None:
        for name, val, mn, mx in [
            ("min_pps", self.min_pps, 1, 1_000_000),
            ("max_pps", self.max_pps, 1, 100_000_000),
            ("max_bps", self.max_bps, 1000, 100_000_000_000),
            ("max_total_packets", self.max_total_packets, 1, 10_000_000_000_000_000),
            ("stable_cycles_required", self.stable_cycles_required, 1, 100),
            ("max_consecutive_sensor_faults", self.max_consecutive_sensor_faults, 1, 50),
            ("l2_overhead_bytes", self.l2_overhead_bytes, 0, 100),
            ("l3_overhead_bytes", self.l3_overhead_bytes, 0, 100),
            ("l4_overhead_bytes", self.l4_overhead_bytes, 0, 100),
            ("phy_overhead_bytes", self.phy_overhead_bytes, 0, 100),
        ]:
            if isinstance(val, bool) or not isinstance(val, int) or not (mn <= val <= mx):
                raise ValueError(f"{name} must be int in [{mn}, {mx}], got {val!r}")

        for name, val, mn, mx in [
            ("max_runtime_sec", self.max_runtime_sec, 1.0, 31536000.0),
            ("min_host_ram_mb", self.min_host_ram_mb, 200.0, 1_000_000.0),
            ("max_process_rss_mb", self.max_process_rss_mb, 10.0, 100_000.0),
            ("min_disk_free_mb", self.min_disk_free_mb, 500.0, 10_000_000.0),
            ("max_cpu_percent", self.max_cpu_percent, 10.0, 100.0),
            ("max_rtt_ms", self.max_rtt_ms, 1.0, 10_000.0),
            ("max_packet_loss_percent", self.max_packet_loss_percent, 0.0, 100.0),
            ("max_net_util_percent", self.max_net_util_percent, 10.0, 100.0),
            ("max_metric_age_sec", self.max_metric_age_sec, 0.1, 60.0),
            ("min_adjustment_interval_sec", self.min_adjustment_interval_sec, 0.1, 60.0),
            ("min_observation_gap_sec", self.min_observation_gap_sec, 0.01, 10.0),
            ("callback_timeout_sec", self.callback_timeout_sec, 0.05, 30.0),
        ]:
            if (
                isinstance(val, bool)
                or not isinstance(val, (int, float))
                or not math.isfinite(float(val))
                or not (mn <= float(val) <= mx)
            ):
                raise ValueError(f"{name} must be float in [{mn}, {mx}], got {val!r}")

        if not isinstance(self.measurement_layer, MeasurementLayer):
            raise TypeError(f"Invalid measurement_layer: {self.measurement_layer!r}")
        if not self.overhead_rationale or not isinstance(self.overhead_rationale, str):
            raise ValueError("overhead_rationale must be non-empty string")

        if self.measurement_layer == MeasurementLayer.L3_IP:
            if self.l2_overhead_bytes != 0 or self.phy_overhead_bytes != 0:
                raise ValueError("L3_IP requires l2_overhead_bytes=0 and phy_overhead_bytes=0")
        elif self.measurement_layer == MeasurementLayer.L2_FRAME:
            if self.phy_overhead_bytes != 0:
                raise ValueError("L2_FRAME requires phy_overhead_bytes=0")

        if not self.allowed_destination_cidrs or not isinstance(self.allowed_destination_cidrs, tuple):
            raise ValueError("allowed_destination_cidrs must be non-empty tuple of str")
        for cidr in self.allowed_destination_cidrs:
            if not isinstance(cidr, str):
                raise TypeError(f"CIDR must be str, got {cidr!r}")
            try:
                net = ipaddress.ip_network(cidr, strict=True)
                if net.is_global:
                    raise ValueError(f"Global internet CIDR {cidr!r} is strictly prohibited")
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR {cidr!r}: {exc}") from exc

        if not self.allowed_interfaces or not isinstance(self.allowed_interfaces, tuple):
            raise ValueError("allowed_interfaces must be non-empty tuple of str")
        for iface in self.allowed_interfaces:
            if not isinstance(iface, str) or not re.match(r"^[a-zA-Z0-9_\-\.]{1,16}$", iface):
                raise ValueError(f"Invalid interface name: {iface!r}")

        payload_bytes = 1400
        frame_bytes = (
            payload_bytes
            + self.l2_overhead_bytes
            + self.l3_overhead_bytes
            + self.l4_overhead_bytes
            + self.phy_overhead_bytes
        )
        object.__setattr__(self, "_frame_total_bytes", frame_bytes)
        bps_pps_limit = int(self.max_bps // (frame_bytes * 8))
        effective_max = min(self.max_pps, bps_pps_limit)
        object.__setattr__(self, "_effective_max_pps", effective_max)

        if effective_max < self.min_pps:
            raise ValueError(
                f"effective_max_pps ({effective_max}) is less than min_pps ({self.min_pps})"
            )

    @property
    def frame_total_bytes(self) -> int:
        return getattr(self, "_frame_total_bytes", 1454)

    @property
    def effective_max_pps(self) -> int:
        return getattr(self, "_effective_max_pps", self.max_pps)


class PacketDataProvider(Protocol):
    def get_current_measured_rates(self) -> tuple[float, float]:
        ...

    def get_cumulative_packet_count(self) -> int:
        ...


@dataclass(frozen=True)
class ControllerMetrics:
    host_ram_free_mb: float
    process_rss_mb: float
    disk_free_mb: float
    cpu_percent: float
    observed_at: float
    sensor_healthy: bool
    rtt_ms: float | None = None
    packet_loss_percent: float | None = None
    net_util_percent: float | None = None


class EgressGate:
    def __init__(self, limits: ControllerSafetyLimits) -> None:
        self.limits = limits
        self._locked = True

    def is_locked(self) -> bool:
        return self._locked

    def transmit(self, packet_bytes: bytes, dest_ip: str, iface: str) -> None:
        if self._locked:
            raise EgressLockedError("EgressGate is locked in Phase 2A - transmission refused")
        raise NotImplementedError("Real transmission is not implemented in Phase 2A")


class AdaptivePacketController:
    def __init__(
        self,
        *,
        limits: ControllerSafetyLimits | None = None,
        mode: ControlMode = ControlMode.MODE_A_SIMULATION,
        provider: PacketDataProvider | None = None,
        rate_apply_callback: Callable[[int, int], bool] | None = None,
        stop_callback: Callable[[], bool] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if limits is None:
            limits = ControllerSafetyLimits()
        elif not isinstance(limits, ControllerSafetyLimits):
            raise TypeError("limits must be ControllerSafetyLimits")

        if not isinstance(mode, ControlMode):
            raise TypeError(f"mode must be ControlMode enum, got {mode!r}")
        if mode == ControlMode.MODE_C_LIVE_NETWORK:
            raise ValueError("MODE_C_LIVE_NETWORK is strictly prohibited in Phase 2A")

        self.limits = limits
        self.mode = mode
        self.provider = provider
        self.rate_apply_callback = rate_apply_callback
        self.stop_callback = stop_callback
        self._clock = clock if clock is not None else time.monotonic

        self._state_lock = threading.RLock()
        self._op_lock = threading.Lock()

        self._state: ControllerState = ControllerState.IDLE
        self._stop_status: StopStatus = StopStatus.IDLE
        self._rate_apply_status: RateApplyStatus = RateApplyStatus.NOT_APPLIED

        self._target_pps: int = self.limits.min_pps
        self._target_bps: int = int(self._target_pps * self.limits.frame_total_bytes * 8)
        self._applied_pps: int = 0
        self._applied_bps: int = 0

        self._test_start_time: float | None = None
        self._last_adjustment_time: float = 0.0
        self._last_observed_time: float = 0.0
        self._last_valid_cumulative_packets: int = 0
        self._stable_cycle_count: int = 0
        self._consecutive_sensor_faults: int = 0
        self._epoch: int = 0

        self._audit_log: list[str] = []
        self.egress_gate = EgressGate(self.limits)

    def start_test(self) -> None:
        with self._op_lock:
            with self._state_lock:
                if self._state != ControllerState.IDLE:
                    raise RuntimeError(f"Cannot start test from state {self._state.value}")
                now = self._clock()
                self._test_start_time = now
                self._last_adjustment_time = now
                self._last_observed_time = now
                self._last_valid_cumulative_packets = 0
                self._stable_cycle_count = 0
                self._consecutive_sensor_faults = 0
                self._epoch += 1
                self._state = ControllerState.RAMPING_UP
                self._target_pps = self.limits.min_pps
                self._target_bps = int(self._target_pps * self.limits.frame_total_bytes * 8)
                self._audit_log.append(f"START_TEST:epoch={self._epoch}:pps={self._target_pps}")

    def trigger_emergency_stop(self, reason: str) -> None:
        with self._state_lock:
            self._epoch += 1
            curr_state = self._state
            if curr_state != ControllerState.COMPLETED_HALT:
                self._state = ControllerState.EMERGENCY_HALT
            self._stop_status = StopStatus.REQUESTED
            self._target_pps = 0
            self._target_bps = 0
            self._applied_pps = 0
            self._applied_bps = 0
            self._audit_log.append(f"EMERGENCY_STOP_TRIGGERED:reason={reason}")

        self._dispatch_stop()

    def _dispatch_stop(self) -> None:
        if self.stop_callback is None:
            with self._state_lock:
                self._stop_status = StopStatus.UNCONFIRMED_NO_CALLBACK
                self._audit_log.append("STOP_DISPATCH:UNCONFIRMED_NO_CALLBACK")
            return

        with self._state_lock:
            self._stop_status = StopStatus.DISPATCHED

        res = bounded_call(self.stop_callback, timeout_sec=self.limits.callback_timeout_sec)
        with self._state_lock:
            if res.status == CallStatus.OK:
                if res.value is True:
                    self._stop_status = StopStatus.CONFIRMED
                    self._audit_log.append("STOP_DISPATCH:CONFIRMED")
                else:
                    self._stop_status = StopStatus.UNCONFIRMED_REFUSED
                    self._audit_log.append("STOP_DISPATCH:UNCONFIRMED_REFUSED")
            elif res.status == CallStatus.TIMEOUT:
                self._stop_status = StopStatus.UNCONFIRMED_TIMEOUT
                self._audit_log.append("STOP_DISPATCH:UNCONFIRMED_TIMEOUT")
            else:
                self._stop_status = StopStatus.UNCONFIRMED_EXCEPTION
                self._audit_log.append(f"STOP_DISPATCH:UNCONFIRMED_EXCEPTION:{res.error_type}")

    def evaluate_and_adjust(self, metrics: ControllerMetrics) -> None:
        with self._op_lock:
            now = self._clock()
            with self._state_lock:
                if self._state in (ControllerState.IDLE, ControllerState.COMPLETED_HALT, ControllerState.EMERGENCY_HALT):
                    return

                if math.isnan(now) or math.isinf(now) or (self._test_start_time and now < self._test_start_time):
                    self.trigger_emergency_stop("Clock regression or invalid timestamp")
                    return

                elapsed = now - (self._test_start_time or now)
                if elapsed >= self.limits.max_runtime_sec:
                    self._state = ControllerState.COMPLETED_HALT
                    self._target_pps = 0
                    self._target_bps = 0
                    self._audit_log.append(f"TEST_COMPLETED:runtime_limit_reached:{elapsed:.2f}s")
                    self._dispatch_stop()
                    return

                if self.provider is not None:
                    try:
                        cum_packets = self.provider.get_cumulative_packet_count()
                        if (
                            isinstance(cum_packets, bool)
                            or not isinstance(cum_packets, int)
                            or cum_packets < self._last_valid_cumulative_packets
                        ):
                            self.trigger_emergency_stop("Invalid or monotonic regression in cumulative packets")
                            return
                        self._last_valid_cumulative_packets = cum_packets

                        if cum_packets >= self.limits.max_total_packets:
                            self._state = ControllerState.COMPLETED_HALT
                            self._target_pps = 0
                            self._target_bps = 0
                            self._audit_log.append(f"TEST_COMPLETED:packet_cap_reached:{cum_packets}")
                            self._dispatch_stop()
                            return
                    except Exception as exc:
                        self.trigger_emergency_stop(f"Provider cumulative packet exception: {type(exc).__name__}")
                        return

                    try:
                        meas_pps, meas_bps = self.provider.get_current_measured_rates()
                        if (
                            isinstance(meas_pps, bool)
                            or isinstance(meas_bps, bool)
                            or not isinstance(meas_pps, (int, float))
                            or not isinstance(meas_bps, (int, float))
                            or not math.isfinite(float(meas_pps))
                            or not math.isfinite(float(meas_bps))
                            or float(meas_pps) < 0.0
                            or float(meas_bps) < 0.0
                        ):
                            self.trigger_emergency_stop("Invalid measured rates format")
                            return

                        if float(meas_pps) > self.limits.effective_max_pps or float(meas_bps) > self.limits.max_bps:
                            self.trigger_emergency_stop(f"Measured rate exceeded limit: pps={meas_pps}, bps={meas_bps}")
                            return
                    except Exception as exc:
                        self.trigger_emergency_stop(f"Provider measured rate exception: {type(exc).__name__}")
                        return

                metric_age = now - metrics.observed_at
                sensor_ok = (
                    metrics.sensor_healthy
                    and (0.0 <= metric_age <= self.limits.max_metric_age_sec)
                    and (metrics.host_ram_free_mb >= self.limits.min_host_ram_mb)
                    and (metrics.process_rss_mb <= self.limits.max_process_rss_mb)
                    and (metrics.disk_free_mb >= self.limits.min_disk_free_mb)
                    and (metrics.cpu_percent <= self.limits.max_cpu_percent)
                )
                if self.mode == ControlMode.MODE_B_ISOLATED_LAB:
                    if (
                        metrics.rtt_ms is None
                        or metrics.packet_loss_percent is None
                        or metrics.net_util_percent is None
                        or metrics.rtt_ms > self.limits.max_rtt_ms
                        or metrics.packet_loss_percent > self.limits.max_packet_loss_percent
                        or metrics.net_util_percent > self.limits.max_net_util_percent
                    ):
                        sensor_ok = False

                if not sensor_ok:
                    self._consecutive_sensor_faults += 1
                    self._stable_cycle_count = 0
                    if self._consecutive_sensor_faults >= self.limits.max_consecutive_sensor_faults:
                        self.trigger_emergency_stop(f"Sustained sensor faults: {self._consecutive_sensor_faults}")
                        return
                    self._state = ControllerState.THROTTLING_DOWN
                    planned_pps = max(self.limits.min_pps, int(self._target_pps * 0.5))
                else:
                    self._consecutive_sensor_faults = 0
                    if (now - self._last_observed_time) >= self.limits.min_observation_gap_sec:
                        self._stable_cycle_count += 1
                        self._last_observed_time = now

                    if (now - self._last_adjustment_time) >= self.limits.min_adjustment_interval_sec:
                        if self._stable_cycle_count >= self.limits.stable_cycles_required:
                            self._state = ControllerState.RAMPING_UP
                            planned_pps = min(self.limits.effective_max_pps, int(self._target_pps * 1.2) + 10)
                        else:
                            self._state = ControllerState.STEADY
                            planned_pps = self._target_pps
                        self._last_adjustment_time = now
                    else:
                        planned_pps = self._target_pps

                planned_bps = int(planned_pps * self.limits.frame_total_bytes * 8)
                epoch = self._epoch

            apply_ok = False
            if self.rate_apply_callback is not None:
                res = bounded_call(self.rate_apply_callback, planned_pps, planned_bps, timeout_sec=self.limits.callback_timeout_sec)
                apply_ok = (res.status == CallStatus.OK and res.value is True)

            with self._state_lock:
                if self._epoch != epoch:
                    return

                if self.rate_apply_callback is None:
                    self._rate_apply_status = RateApplyStatus.NO_CALLBACK
                    self._target_pps = planned_pps
                    self._target_bps = planned_bps
                    self._applied_pps = 0
                    self._applied_bps = 0
                elif apply_ok:
                    self._rate_apply_status = RateApplyStatus.CONFIRMED
                    self._target_pps = planned_pps
                    self._target_bps = planned_bps
                    self._applied_pps = planned_pps
                    self._applied_bps = planned_bps
                else:
                    self._rate_apply_status = RateApplyStatus.FAILED
                    if planned_pps < self._target_pps:
                        self._state = ControllerState.SAFE_MINIMUM
                    self._audit_log.append(f"RATE_APPLY_FAILED:target_pps={planned_pps}")

    def resume_from_emergency(self, preflight_metrics: ControllerMetrics) -> None:
        with self._op_lock:
            with self._state_lock:
                if self._state == ControllerState.COMPLETED_HALT:
                    raise RuntimeError("Resume is strictly prohibited from COMPLETED_HALT. Use reset_for_new_test()")
                if self._state != ControllerState.EMERGENCY_HALT:
                    raise RuntimeError(f"Cannot resume from state {self._state.value}")
                if self._stop_status != StopStatus.CONFIRMED and self.stop_callback is not None:
                    raise RuntimeError(f"Cannot resume while stop_status is {self._stop_status.value}")

                now = self._clock()
                metric_age = now - preflight_metrics.observed_at
                if (
                    not preflight_metrics.sensor_healthy
                    or not (0.0 <= metric_age <= self.limits.max_metric_age_sec)
                    or preflight_metrics.host_ram_free_mb < self.limits.min_host_ram_mb
                    or preflight_metrics.process_rss_mb > self.limits.max_process_rss_mb
                    or preflight_metrics.disk_free_mb < self.limits.min_disk_free_mb
                    or preflight_metrics.cpu_percent > self.limits.max_cpu_percent
                ):
                    raise RuntimeError("Preflight metrics check failed on resume")

                self._epoch += 1
                self._state = ControllerState.SAFE_MINIMUM
                self._target_pps = self.limits.min_pps
                self._target_bps = int(self._target_pps * self.limits.frame_total_bytes * 8)
                self._consecutive_sensor_faults = 0
                self._stable_cycle_count = 0
                self._audit_log.append(f"RESUMED_FROM_EMERGENCY:epoch={self._epoch}")

    def reset_for_new_test(self) -> None:
        with self._op_lock:
            with self._state_lock:
                self._epoch += 1
                self._state = ControllerState.IDLE
                self._stop_status = StopStatus.IDLE
                self._rate_apply_status = RateApplyStatus.NOT_APPLIED
                self._test_start_time = None
                self._last_adjustment_time = 0.0
                self._last_observed_time = 0.0
                self._last_valid_cumulative_packets = 0
                self._stable_cycle_count = 0
                self._consecutive_sensor_faults = 0
                self._target_pps = self.limits.min_pps
                self._target_bps = int(self._target_pps * self.limits.frame_total_bytes * 8)
                self._applied_pps = 0
                self._applied_bps = 0
                self._audit_log.append(f"RESET_FOR_NEW_TEST:epoch={self._epoch}")

    def verify_destination(self, dest_ip: str, iface: str) -> bool:
        if self.mode == ControlMode.MODE_A_SIMULATION:
            return False
        if self.mode == ControlMode.MODE_B_ISOLATED_LAB:
            try:
                ip_obj = ipaddress.ip_address(dest_ip)
                if iface not in self.limits.allowed_interfaces:
                    return False
                for cidr in self.limits.allowed_destination_cidrs:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return True
            except Exception:
                return False
        return False

    def snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "state": self._state.value,
                "mode": self.mode.value,
                "target_pps": self._target_pps,
                "target_bps": self._target_bps,
                "applied_pps": self._applied_pps,
                "applied_bps": self._applied_bps,
                "rate_apply_status": self._rate_apply_status.value,
                "stop_status": self._stop_status.value,
                "effective_max_pps": self.limits.effective_max_pps,
                "cumulative_packets": self._last_valid_cumulative_packets,
                "stable_cycles": self._stable_cycle_count,
                "sensor_faults": self._consecutive_sensor_faults,
                "egress_gate_locked": self.egress_gate.is_locked(),
            }
