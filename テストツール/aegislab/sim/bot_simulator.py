"""Virtual Sender Agent Simulator (1..10^16 Bots) & 10Gbps Theoretical Model (Module 8).

Enforces:
- Bot count range: 1 to 10^16 (1京 = 10,000,000,000,000,000).
- O(1) memory representation via hierarchical group summaries (max 64 groups).
- Never spawns 10^16 VMs, processes, or threads.
- Explicitly separates:
    * target_virtual_bots
    * modeled_bots
    * actual_logical_agents
    * actual_spawned_processes (0 in Phase 2A)
    * actual_running_vms (0 in Phase 2A)
- Exact theoretical rate formula:
    R_theoretical = N * 10 Gbps = N * 10^10 bit/s
  At N = 10^16: 10^17 Gbps = 10^26 bit/s.
- Mandatory 5-way separation: THEORETICAL, SIMULATED, MEASURED (None), UNMEASURABLE, UNVERIFIED.
"""

from __future__ import annotations

from dataclasses import dataclass
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

PER_BOT_THEORETICAL_GBPS: int = 10
PER_BOT_THEORETICAL_BPS: int = 10 * (10**9)  # 10^10 bit/s
MAX_LOGICAL_GROUPS: int = 64


@dataclass(frozen=True)
class BotGroupSummary:
    group_id: str
    bot_count: str
    active_count: str
    stopped_count: str
    uncreated_count: str
    error_count: str

    def to_dict(self) -> dict[str, str]:
        return {
            "group_id": self.group_id,
            "bot_count": self.bot_count,
            "active_count": self.active_count,
            "stopped_count": self.stopped_count,
            "uncreated_count": self.uncreated_count,
            "error_count": self.error_count,
        }


@dataclass(frozen=True)
class BotSimulationSnapshot:
    target_virtual_bots: str
    target_virtual_bots_jp: str
    modeled_bots: str
    actual_logical_agents: int
    actual_spawned_processes: int
    actual_running_vms: int
    state_counts: dict[str, str]
    group_summaries: tuple[BotGroupSummary, ...]
    total_modeled_packets: str
    total_individually_processed_packets: str
    rates_five_way: dict[str, LabeledMetric]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_virtual_bots": self.target_virtual_bots,
            "target_virtual_bots_jp": self.target_virtual_bots_jp,
            "modeled_bots": self.modeled_bots,
            "actual_logical_agents": self.actual_logical_agents,
            "actual_spawned_processes": self.actual_spawned_processes,
            "actual_running_vms": self.actual_running_vms,
            "state_counts": dict(self.state_counts),
            "group_summaries": [g.to_dict() for g in self.group_summaries],
            "total_modeled_packets": self.total_modeled_packets,
            "total_individually_processed_packets": self.total_individually_processed_packets,
            "rates_five_way": {
                k: v.to_dict() for k, v in self.rates_five_way.items()
            },
        }


class VirtualBotSimulator:
    """Aggregate mathematical and state-vector simulator for 1..10^16 virtual bots."""

    def __init__(
        self,
        target_virtual_bots: int | str,
        *,
        group_count: int = 8,
    ) -> None:
        self._target_bots: int = parse_exact_decimal_int(
            target_virtual_bots,
            field_name="target_virtual_bots",
            min_val=MIN_COUNT_INT,
            max_val=MAX_COUNT_INT,
        )
        if group_count < 1 or group_count > MAX_LOGICAL_GROUPS:
            raise ValueError(f"group_count must be between 1 and {MAX_LOGICAL_GROUPS}")
        self._actual_groups: int = min(group_count, self._target_bots)

        # Initial state: all bots are uncreated (initial OFF policy)
        self._active: int = 0
        self._stopped: int = 0
        self._uncreated: int = self._target_bots
        self._error: int = 0
        self._total_modeled_packets: int = 0
        self._total_individual_packets: int = 0
        self._simulated_rate_bps: int = 0

    @property
    def target_bots(self) -> int:
        return self._target_bots

    @property
    def theoretical_rate_gbps(self) -> int:
        return self._target_bots * PER_BOT_THEORETICAL_GBPS

    @property
    def theoretical_rate_bps(self) -> int:
        return self._target_bots * PER_BOT_THEORETICAL_BPS

    def transition_states(
        self,
        *,
        active: int | str,
        stopped: int | str,
        uncreated: int | str,
        error: int | str,
        modeled_packets_delta: int | str = 0,
        simulated_rate_bps: int | str = 0,
    ) -> BotSimulationSnapshot:
        """Update aggregate bot state distribution while preserving total == target_bots."""
        a = parse_exact_decimal_int(active, field_name="active", min_val=0, max_val=MAX_COUNT_INT)
        s = parse_exact_decimal_int(stopped, field_name="stopped", min_val=0, max_val=MAX_COUNT_INT)
        u = parse_exact_decimal_int(uncreated, field_name="uncreated", min_val=0, max_val=MAX_COUNT_INT)
        e = parse_exact_decimal_int(error, field_name="error", min_val=0, max_val=MAX_COUNT_INT)
        pkt_d = parse_exact_decimal_int(
            modeled_packets_delta, field_name="modeled_packets_delta", min_val=0, max_val=MAX_COUNT_INT
        )
        sim_bps = parse_exact_decimal_int(
            simulated_rate_bps, field_name="simulated_rate_bps", min_val=0, max_val=10**27
        )

        if a + s + u + e != self._target_bots:
            raise ValueError(
                f"Bot state sum ({a + s + u + e}) must equal target_virtual_bots ({self._target_bots})"
            )

        self._active = a
        self._stopped = s
        self._uncreated = u
        self._error = e
        self._total_modeled_packets += pkt_d
        self._simulated_rate_bps = sim_bps
        return self.snapshot()

    def _build_group_summaries(self) -> tuple[BotGroupSummary, ...]:
        g_count = self._actual_groups
        base_total, rem_total = divmod(self._target_bots, g_count)
        base_a, rem_a = divmod(self._active, g_count)
        base_s, rem_s = divmod(self._stopped, g_count)
        base_u, rem_u = divmod(self._uncreated, g_count)
        base_e, rem_e = divmod(self._error, g_count)

        groups: list[BotGroupSummary] = []
        for idx in range(g_count):
            g_tot = base_total + (1 if idx < rem_total else 0)
            g_a = base_a + (1 if idx < rem_a else 0)
            g_s = base_s + (1 if idx < rem_s else 0)
            g_u = base_u + (1 if idx < rem_u else 0)
            g_e = base_e + (1 if idx < rem_e else 0)
            groups.append(
                BotGroupSummary(
                    group_id=f"bot-cluster-{idx + 1:02d}",
                    bot_count=str(g_tot),
                    active_count=str(g_a),
                    stopped_count=str(g_s),
                    uncreated_count=str(g_u),
                    error_count=str(g_e),
                )
            )
        return tuple(groups)

    def snapshot(self) -> BotSimulationSnapshot:
        theo_gbps_str = str(self.theoretical_rate_gbps)
        theo_bps_str = str(self.theoretical_rate_bps)

        rates_five_way: dict[str, LabeledMetric] = {
            "theoretical_gbps": LabeledMetric(
                name="theoretical_aggregate_rate_gbps",
                category=MetricCategory.THEORETICAL,
                value_str=theo_gbps_str,
                unit="Gbps",
                note=(
                    f"Mathematical formula R_theoretical = N * 10 Gbps ({theo_bps_str} bit/s). "
                    "Not an achievable physical network speed."
                ),
                verification_status=Verdict.PASS,
            ),
            "theoretical_bps": LabeledMetric(
                name="theoretical_aggregate_rate_bps",
                category=MetricCategory.THEORETICAL,
                value_str=theo_bps_str,
                unit="bit/s",
                note="Exact base-10 bit/s value of N * 10 Gbps.",
                verification_status=Verdict.PASS,
            ),
            "simulated_bps": LabeledMetric(
                name="simulated_model_rate_bps",
                category=MetricCategory.SIMULATED,
                value_str=str(self._simulated_rate_bps),
                unit="bit/s (modeled)",
                note="In-memory statistical model throughput. Zero packets transmitted on wire.",
                verification_status=Verdict.PASS,
            ),
            "measured_bps": LabeledMetric(
                name="empirical_measured_network_rate_bps",
                category=MetricCategory.UNVERIFIED,
                value_str=None,
                unit="bit/s",
                note="Real network transmission is prohibited and OFF in Phase 2A (NOT TESTED).",
                verification_status=Verdict.NOT_TESTED,
            ),
            "physical_100_exa_bps": LabeledMetric(
                name="physical_wire_realization_at_max_scale",
                category=MetricCategory.UNMEASURABLE,
                value_str=None,
                unit="bit/s",
                note="Exceeds physical NIC and hardware limits; cannot be empirically measured.",
                verification_status=Verdict.NOT_TESTED,
            ),
        }

        return BotSimulationSnapshot(
            target_virtual_bots=str(self._target_bots),
            target_virtual_bots_jp=format_japanese_large_number(self._target_bots),
            modeled_bots=str(self._target_bots),
            actual_logical_agents=self._actual_groups,
            actual_spawned_processes=0,
            actual_running_vms=0,
            state_counts={
                "active": str(self._active),
                "stopped": str(self._stopped),
                "uncreated": str(self._uncreated),
                "error": str(self._error),
            },
            group_summaries=self._build_group_summaries(),
            total_modeled_packets=str(self._total_modeled_packets),
            total_individually_processed_packets=str(self._total_individual_packets),
            rates_five_way=rates_five_way,
        )
