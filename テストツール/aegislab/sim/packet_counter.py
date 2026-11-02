"""Exact Arbitrary-Precision Packet Counter & Streaming Aggregator (1..10^16) (Module 7).

Enforces:
- Target range 1 to 10^16 (1京 = 10,000,000,000,000,000) without float rounding.
- 11 independent counter items with strict step-by-step invariant verification:
    0 <= completed == (succeeded + dropped + error) <= started <= generated <= target <= 10^16
    remaining == target - completed
- O(1) memory footprint: never allocates per-packet arrays in memory.
- Strict separation between `individually_processed_packets` and `modeled_statistical_packets`.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, getcontext
from typing import Any

from aegislab.core.value_types import (
    LabeledMetric,
    MAX_COUNT_INT,
    MIN_COUNT_INT,
    MetricCategory,
    Verdict,
    format_japanese_large_number,
    parse_exact_decimal_int,
)

# High decimal precision (50 digits) for rate & ETA calculations without float loss
getcontext().prec = 50


class CounterInvariantError(RuntimeError):
    """Raised when packet counter invariants are violated."""


@dataclass(frozen=True)
class PacketCounterSnapshot:
    """Immutable snapshot of all 11 required packet counter fields as exact decimal strings."""

    target_packets: str
    target_packets_jp: str
    generated_packets: str
    started_packets: str
    completed_packets: str
    succeeded_packets: str
    dropped_packets: str
    error_packets: str
    remaining_packets: str
    current_rate_pps: LabeledMetric
    elapsed_ns: str
    estimated_remaining_sec: str
    individually_processed_packets: str
    modeled_statistical_packets: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_packets": self.target_packets,
            "target_packets_jp": self.target_packets_jp,
            "generated_packets": self.generated_packets,
            "started_packets": self.started_packets,
            "completed_packets": self.completed_packets,
            "succeeded_packets": self.succeeded_packets,
            "dropped_packets": self.dropped_packets,
            "error_packets": self.error_packets,
            "remaining_packets": self.remaining_packets,
            "current_rate_pps": self.current_rate_pps.to_dict(),
            "elapsed_ns": self.elapsed_ns,
            "estimated_remaining_sec": self.estimated_remaining_sec,
            "individually_processed_packets": self.individually_processed_packets,
            "modeled_statistical_packets": self.modeled_statistical_packets,
        }


class PacketCounterEngine:
    """Manages exact integer counters from 1 to 10^16 with O(1) memory."""

    def __init__(self, target_packets: int | str) -> None:
        self._target: int = parse_exact_decimal_int(
            target_packets,
            field_name="target_packets",
            min_val=MIN_COUNT_INT,
            max_val=MAX_COUNT_INT,
        )
        self._generated: int = 0
        self._started: int = 0
        self._succeeded: int = 0
        self._dropped: int = 0
        self._error: int = 0
        self._elapsed_ns: int = 0
        self._individually_processed: int = 0
        self._modeled_statistical: int = 0
        self._verify_invariants()

    @property
    def target(self) -> int:
        return self._target

    @property
    def completed(self) -> int:
        return self._succeeded + self._dropped + self._error

    @property
    def remaining(self) -> int:
        return self._target - self.completed

    def _verify_invariants(self) -> None:
        comp = self.completed
        if any(
            x < 0
            for x in (
                self._generated,
                self._started,
                self._succeeded,
                self._dropped,
                self._error,
                self._elapsed_ns,
                self._individually_processed,
                self._modeled_statistical,
            )
        ):
            raise CounterInvariantError("Negative counter value detected")
        if comp > self._started:
            raise CounterInvariantError(
                f"Invariant violation: completed ({comp}) > started ({self._started})"
            )
        if self._started > self._generated:
            raise CounterInvariantError(
                f"Invariant violation: started ({self._started}) > generated ({self._generated})"
            )
        if self._generated > self._target:
            raise CounterInvariantError(
                f"Invariant violation: generated ({self._generated}) > target ({self._target})"
            )
        if self._individually_processed + self._modeled_statistical != comp:
            raise CounterInvariantError(
                "Invariant violation: (individually_processed + modeled_statistical) != completed"
            )

    def record_batch(
        self,
        *,
        generated_delta: int | str,
        started_delta: int | str,
        succeeded_delta: int | str,
        dropped_delta: int | str,
        error_delta: int | str,
        elapsed_ns_delta: int | str,
        is_modeled_statistical: bool = True,
    ) -> PacketCounterSnapshot:
        """Advance counters by an exact batch delta and verify all invariants."""
        g_d = parse_exact_decimal_int(
            generated_delta, field_name="generated_delta", min_val=0, max_val=MAX_COUNT_INT
        )
        st_d = parse_exact_decimal_int(
            started_delta, field_name="started_delta", min_val=0, max_val=MAX_COUNT_INT
        )
        ok_d = parse_exact_decimal_int(
            succeeded_delta, field_name="succeeded_delta", min_val=0, max_val=MAX_COUNT_INT
        )
        dr_d = parse_exact_decimal_int(
            dropped_delta, field_name="dropped_delta", min_val=0, max_val=MAX_COUNT_INT
        )
        er_d = parse_exact_decimal_int(
            error_delta, field_name="error_delta", min_val=0, max_val=MAX_COUNT_INT
        )
        ns_d = parse_exact_decimal_int(
            elapsed_ns_delta, field_name="elapsed_ns_delta", min_val=0, max_val=10**24
        )

        comp_d = ok_d + dr_d + er_d
        new_gen = self._generated + g_d
        new_st = self._started + st_d
        new_ok = self._succeeded + ok_d
        new_dr = self._dropped + dr_d
        new_er = self._error + er_d
        new_comp = new_ok + new_dr + new_er
        new_ind = self._individually_processed + (0 if is_modeled_statistical else comp_d)
        new_mod = self._modeled_statistical + (comp_d if is_modeled_statistical else 0)

        if new_comp > new_st or new_st > new_gen or new_gen > self._target:
            raise CounterInvariantError(
                "Batch transition would violate ordering invariant "
                f"(comp={new_comp}, started={new_st}, gen={new_gen}, target={self._target})"
            )

        self._generated = new_gen
        self._started = new_st
        self._succeeded = new_ok
        self._dropped = new_dr
        self._error = new_er
        self._elapsed_ns += ns_d
        self._individually_processed = new_ind
        self._modeled_statistical = new_mod
        self._verify_invariants()
        return self.snapshot()

    def snapshot(self) -> PacketCounterSnapshot:
        comp = self.completed
        rem = self.remaining
        if self._elapsed_ns > 0 and comp > 0:
            rate_dec = (Decimal(comp) * Decimal(10**9)) / Decimal(self._elapsed_ns)
            rate_str = f"{rate_dec:.2f}"
            eta_dec = Decimal(rem) / rate_dec if rate_dec > 0 else Decimal(0)
            eta_str = f"{eta_dec:.2f}"
        else:
            rate_str = "0.00"
            eta_str = "0.00" if rem == 0 else "N/A (Stalled or Not Started)"

        rate_metric = LabeledMetric(
            name="current_packet_processing_rate",
            category=MetricCategory.SIMULATED,
            value_str=rate_str,
            unit="pps (simulated)",
            note=(
                "Simulated batch accounting rate in memory. "
                "Real network packet transmission is OFF (NOT TESTED in Phase 2A)."
            ),
            verification_status=Verdict.PASS,
        )

        return PacketCounterSnapshot(
            target_packets=str(self._target),
            target_packets_jp=format_japanese_large_number(self._target),
            generated_packets=str(self._generated),
            started_packets=str(self._started),
            completed_packets=str(comp),
            succeeded_packets=str(self._succeeded),
            dropped_packets=str(self._dropped),
            error_packets=str(self._error),
            remaining_packets=str(rem),
            current_rate_pps=rate_metric,
            elapsed_ns=str(self._elapsed_ns),
            estimated_remaining_sec=eta_str,
            individually_processed_packets=str(self._individually_processed),
            modeled_statistical_packets=str(self._modeled_statistical),
        )
