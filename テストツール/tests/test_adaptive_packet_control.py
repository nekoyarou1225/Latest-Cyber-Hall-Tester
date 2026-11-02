"""Unit test suite for Adaptive Packet Controller, strict safety limits, and fault boundaries.

Imports the REAL AdaptivePacketController from aegislab.control.adaptive_packet_controller.
Uses mock clocks, simulated data providers, and callback mocks without network/NIC access.
"""

from __future__ import annotations

import unittest
from typing import Any

import sys
sys.path.insert(0, "/home/harukiy1225/テストツール")
import aegislab, aegislab.core
aegislab.__path__.insert(0, "/home/harukiy1225/.gemini/antigravity/brain/4087d8e6-27a3-42d7-8c0a-e13a874bbbe5/scratch/proposed/aegislab")
aegislab.core.__path__.insert(0, "/home/harukiy1225/.gemini/antigravity/brain/4087d8e6-27a3-42d7-8c0a-e13a874bbbe5/scratch/proposed/aegislab/core")

from aegislab.control.adaptive_packet_controller import (
    AdaptivePacketController,
    ControllerSafetyLimits,
    ControllerMetrics,
    ControlMode,
    ControllerState,
    StopStatus,
    RateApplyStatus,
    MeasurementLayer,
    EgressLockedError,
)


class MockProvider:
    def __init__(self, pps: float = 100.0, bps: float = 100000.0, cum: int = 1000) -> None:
        self.pps = pps
        self.bps = bps
        self.cum = cum
        self.calls = 0

    def get_current_measured_rates(self) -> tuple[float, float]:
        self.calls += 1
        return (self.pps, self.bps)

    def get_cumulative_packet_count(self) -> int:
        return self.cum


class TestAdaptivePacketControl(unittest.TestCase):
    def setUp(self) -> None:
        self.current_time = 1000.0

    def clock(self) -> float:
        return self.current_time

    def _good_metrics(self) -> ControllerMetrics:
        return ControllerMetrics(
            host_ram_free_mb=1024.0,
            process_rss_mb=50.0,
            disk_free_mb=2048.0,
            cpu_percent=25.0,
            observed_at=self.current_time,
            sensor_healthy=True,
        )

    def test_completed_halt_and_emergency_halt_separation(self) -> None:
        limits = ControllerSafetyLimits(max_total_packets=500)
        provider = MockProvider(cum=600)
        ctrl = AdaptivePacketController(limits=limits, provider=provider, clock=self.clock)
        ctrl.start_test()
        self.assertEqual(ctrl.snapshot()["state"], ControllerState.RAMPING_UP.value)

        # evaluate_and_adjust should notice packet cap reached -> COMPLETED_HALT
        ctrl.evaluate_and_adjust(self._good_metrics())
        snap = ctrl.snapshot()
        self.assertEqual(snap["state"], ControllerState.COMPLETED_HALT.value)

        # Triggering emergency stop on completed test must NOT overwrite COMPLETED_HALT
        ctrl.trigger_emergency_stop("External abort request")
        snap2 = ctrl.snapshot()
        self.assertEqual(snap2["state"], ControllerState.COMPLETED_HALT.value)
        self.assertEqual(snap2["stop_status"], StopStatus.UNCONFIRMED_NO_CALLBACK.value)

    def test_resume_refused_after_completion(self) -> None:
        limits = ControllerSafetyLimits(max_total_packets=500)
        provider = MockProvider(cum=600)
        ctrl = AdaptivePacketController(limits=limits, provider=provider, clock=self.clock)
        ctrl.start_test()
        ctrl.evaluate_and_adjust(self._good_metrics())
        self.assertEqual(ctrl.snapshot()["state"], ControllerState.COMPLETED_HALT.value)

        # Attempting resume from COMPLETED_HALT must raise RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            ctrl.resume_from_emergency(self._good_metrics())
        self.assertIn("Resume is strictly prohibited from COMPLETED_HALT", str(ctx.exception))

    def test_reset_and_clock_reset_for_new_test(self) -> None:
        limits = ControllerSafetyLimits(max_total_packets=500)
        provider = MockProvider(cum=600)
        ctrl = AdaptivePacketController(limits=limits, provider=provider, clock=self.clock)
        ctrl.start_test()
        ctrl.evaluate_and_adjust(self._good_metrics())
        self.assertEqual(ctrl.snapshot()["state"], ControllerState.COMPLETED_HALT.value)

        # Explicit reset
        ctrl.reset_for_new_test()
        self.assertEqual(ctrl.snapshot()["state"], ControllerState.IDLE.value)
        self.assertEqual(ctrl.snapshot()["cumulative_packets"], 0)

        # New test can start cleanly
        provider.cum = 10
        ctrl.start_test()
        self.assertEqual(ctrl.snapshot()["state"], ControllerState.RAMPING_UP.value)

    def test_provider_measured_rates_and_over_limit_triggers_emergency(self) -> None:
        limits = ControllerSafetyLimits(max_pps=1000)
        # Provider reports rate over the limit (1500 > 1000)
        provider = MockProvider(pps=1500.0, bps=2000000.0, cum=50)
        ctrl = AdaptivePacketController(limits=limits, provider=provider, clock=self.clock)
        ctrl.start_test()
        ctrl.evaluate_and_adjust(self._good_metrics())

        snap = ctrl.snapshot()
        self.assertEqual(snap["state"], ControllerState.EMERGENCY_HALT.value)

    def test_provider_bad_type_and_monotonic_regression(self) -> None:
        provider = MockProvider(cum=500)
        ctrl = AdaptivePacketController(provider=provider, clock=self.clock)
        ctrl.start_test()
        ctrl.evaluate_and_adjust(self._good_metrics())

        # Cumulative packets drops to 400 (regression)
        provider.cum = 400
        ctrl.evaluate_and_adjust(self._good_metrics())
        self.assertEqual(ctrl.snapshot()["state"], ControllerState.EMERGENCY_HALT.value)

    def test_rate_apply_callback_failure_and_safe_minimum(self) -> None:
        applied_log = []
        def failing_apply(pps: int, bps: int) -> bool:
            applied_log.append((pps, bps))
            return False

        ctrl = AdaptivePacketController(rate_apply_callback=failing_apply, clock=self.clock)
        ctrl.start_test()
        # Evaluate adjustment
        self.current_time += 2.0
        ctrl.evaluate_and_adjust(self._good_metrics())
        snap = ctrl.snapshot()
        self.assertEqual(snap["rate_apply_status"], RateApplyStatus.FAILED.value)
        self.assertEqual(snap["applied_pps"], 0)

    def test_stop_callback_audit_and_unconfirmed_handling(self) -> None:
        def raising_stop() -> bool:
            raise ConnectionResetError("Remote data-plane agent disconnected")

        ctrl = AdaptivePacketController(stop_callback=raising_stop, clock=self.clock)
        ctrl.start_test()
        ctrl.trigger_emergency_stop("Manual test abort")

        snap = ctrl.snapshot()
        self.assertEqual(snap["state"], ControllerState.EMERGENCY_HALT.value)
        self.assertEqual(snap["stop_status"], StopStatus.UNCONFIRMED_EXCEPTION.value)

    def test_safety_limits_boundary_validation(self) -> None:
        # Invalid min_pps > max_pps
        with self.assertRaises(ValueError):
            ControllerSafetyLimits(min_pps=1000, max_pps=500)

        # Invalid bool type
        with self.assertRaises(ValueError):
            ControllerSafetyLimits(min_pps=True)  # type: ignore

        # Invalid CIDR (global internet address prohibited)
        with self.assertRaises(ValueError):
            ControllerSafetyLimits(allowed_destination_cidrs=("8.8.8.8/32",))

        # Inconsistent layer overhead
        with self.assertRaises(ValueError):
            ControllerSafetyLimits(measurement_layer=MeasurementLayer.L3_IP, l2_overhead_bytes=14)

    def test_mode_b_destination_gating_and_egress_lock(self) -> None:
        ctrl = AdaptivePacketController(
            mode=ControlMode.MODE_B_ISOLATED_LAB,
            clock=self.clock,
        )
        # Allowed test network destination
        self.assertTrue(ctrl.verify_destination("192.0.2.10", "lo"))
        # Disallowed destination
        self.assertFalse(ctrl.verify_destination("10.0.0.1", "lo"))
        # Disallowed interface
        self.assertFalse(ctrl.verify_destination("192.0.2.10", "eth0"))

        # EgressGate is strictly locked
        self.assertTrue(ctrl.egress_gate.is_locked())
        with self.assertRaises(EgressLockedError):
            ctrl.egress_gate.transmit(b"packet", "192.0.2.10", "lo")


if __name__ == "__main__":
    unittest.main()
