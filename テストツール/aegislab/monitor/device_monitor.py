"""Read-Only Device Resource Monitor (Module 13).

Enforces:
- User-facing monitoring panel is OFF by default, while mandatory application-level
  resource thresholds remain active in SafetyGuard.
- Strict 3-way separation of:
    1) Battery remaining capacity (%)
    2) Power connection state (Charging / Discharging / External AC Online)
    3) Power consumption (W): separates direct hardware sensor (`DIRECT_SENSOR_UNAVAILABLE`
       when `power_now` is absent) from derived voltage*current (`DERIVED_V_X_I`).
- Never fabricates numbers when OS/hardware/Crostini does not expose a sensor:
    * GPU/VRAM -> `UNSUPPORTED` (`value=None`)
    * Crostini virtualized thermal zone reporting constant `0` -> `UNAVAILABLE` (`value=None`)
    * Outer ChromeOS host state -> `UNVERIFIED_OUTSIDE_CROSTINI_BOUNDARY` (`value=None`)
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import os
from pathlib import Path
from typing import Any


class SensorStatus:
    AVAILABLE = "AVAILABLE"
    DERIVED_FROM_VOLTAGE_CURRENT = "DERIVED_FROM_VOLTAGE_CURRENT"
    DIRECT_SENSOR_UNAVAILABLE = "DIRECT_SENSOR_UNAVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNVERIFIED_OUTSIDE_CROSTINI_BOUNDARY = "UNVERIFIED_OUTSIDE_CROSTINI_BOUNDARY"


@dataclass(frozen=True)
class SensorReading:
    name: str
    status: str
    value: Any
    unit: str
    source_path: str
    note: str

    def __post_init__(self) -> None:
        if self.status in (
            SensorStatus.DIRECT_SENSOR_UNAVAILABLE,
            SensorStatus.UNAVAILABLE,
            SensorStatus.UNSUPPORTED,
            SensorStatus.PERMISSION_DENIED,
            SensorStatus.UNVERIFIED_OUTSIDE_CROSTINI_BOUNDARY,
        ):
            if self.value is not None:
                raise ValueError(
                    f"Sensor '{self.name}' with status {self.status} must have value=None"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "value": self.value,
            "unit": self.unit,
            "source_path": self.source_path,
            "note": self.note,
        }


def _parse_uevent_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


class DeviceMonitor:
    """Reads host/container telemetry strictly in read-only mode without fabricating values."""

    def __init__(self, workspace_dir: Path) -> None:
        self._workspace_dir = workspace_dir

    def read_power_and_battery_separated(
        self,
        *,
        power_supply_root: Path = Path("/sys/class/power_supply"),
    ) -> dict[str, SensorReading]:
        """Return strictly separated (1) battery %, (2) power state, and (3) power W."""
        bat_uevent_path = power_supply_root / "battery" / "uevent"
        ac_uevent_path = power_supply_root / "ac" / "uevent"
        power_now_path = power_supply_root / "battery" / "power_now"

        bat_data = _parse_uevent_file(bat_uevent_path)
        ac_data = _parse_uevent_file(ac_uevent_path)

        # 1. Battery Remaining Capacity (%)
        cap_raw = bat_data.get("POWER_SUPPLY_CAPACITY")
        if cap_raw is not None and cap_raw.isdigit():
            battery_capacity = SensorReading(
                name="battery_capacity_percent",
                status=SensorStatus.AVAILABLE,
                value=int(cap_raw),
                unit="%",
                source_path=str(bat_uevent_path),
                note="Read from POWER_SUPPLY_CAPACITY inside Crostini sysfs.",
            )
        else:
            battery_capacity = SensorReading(
                name="battery_capacity_percent",
                status=SensorStatus.UNAVAILABLE,
                value=None,
                unit="%",
                source_path=str(bat_uevent_path),
                note="Battery capacity not exposed by sysfs.",
            )

        # 2. Power Connection State (Charging / Discharging / External AC)
        bat_status = bat_data.get("POWER_SUPPLY_STATUS")
        ac_online_raw = ac_data.get("POWER_SUPPLY_ONLINE")
        if bat_status is not None or ac_online_raw is not None:
            ac_online = ac_online_raw == "1" if ac_online_raw is not None else None
            power_state = SensorReading(
                name="power_connection_state",
                status=SensorStatus.AVAILABLE,
                value={
                    "battery_status": bat_status or "Unknown",
                    "external_ac_online": ac_online,
                },
                unit="state",
                source_path=f"{bat_uevent_path}, {ac_uevent_path}",
                note="Separated from battery percentage and wattage.",
            )
        else:
            power_state = SensorReading(
                name="power_connection_state",
                status=SensorStatus.UNAVAILABLE,
                value=None,
                unit="state",
                source_path=str(power_supply_root),
                note="Power connection state not exposed.",
            )

        # 3. Power Consumption (W) - Direct sensor vs Derived V*I
        if power_now_path.is_file():
            raw_pw = power_now_path.read_text(encoding="utf-8", errors="replace").strip()
            if raw_pw.isdigit() and int(raw_pw) > 0:
                watts_val = str((Decimal(int(raw_pw)) / Decimal(10**6)).quantize(Decimal("0.01")))
                direct_watts = SensorReading(
                    name="power_consumption_direct_watts",
                    status=SensorStatus.AVAILABLE,
                    value=watts_val,
                    unit="W",
                    source_path=str(power_now_path),
                    note="Direct hardware power_now sensor.",
                )
            else:
                direct_watts = SensorReading(
                    name="power_consumption_direct_watts",
                    status=SensorStatus.DIRECT_SENSOR_UNAVAILABLE,
                    value=None,
                    unit="W",
                    source_path=str(power_now_path),
                    note="power_now returned non-positive or invalid value.",
                )
        else:
            direct_watts = SensorReading(
                name="power_consumption_direct_watts",
                status=SensorStatus.DIRECT_SENSOR_UNAVAILABLE,
                value=None,
                unit="W",
                source_path=str(power_now_path),
                note="Direct power_now sysfs attribute is not present on this platform.",
            )

        v_uv = bat_data.get("POWER_SUPPLY_VOLTAGE_NOW")
        i_ua = bat_data.get("POWER_SUPPLY_CURRENT_NOW")
        if v_uv and i_ua and v_uv.isdigit() and i_ua.isdigit() and int(v_uv) > 0 and int(i_ua) > 0:
            w_dec = (Decimal(int(v_uv)) * Decimal(int(i_ua))) / Decimal(10**12)
            derived_watts = SensorReading(
                name="power_consumption_derived_watts",
                status=SensorStatus.DERIVED_FROM_VOLTAGE_CURRENT,
                value=str(w_dec.quantize(Decimal("0.01"))),
                unit="W (derived V*I)",
                source_path=str(bat_uevent_path),
                note=(
                    "Calculated from POWER_SUPPLY_VOLTAGE_NOW * POWER_SUPPLY_CURRENT_NOW. "
                    "Explicitly distinguished from direct wattmeter sensor."
                ),
            )
        else:
            derived_watts = SensorReading(
                name="power_consumption_derived_watts",
                status=SensorStatus.UNAVAILABLE,
                value=None,
                unit="W (derived V*I)",
                source_path=str(bat_uevent_path),
                note="Voltage or current unavailable for derived calculation.",
            )

        return {
            "battery_capacity_percent": battery_capacity,
            "power_connection_state": power_state,
            "power_consumption_direct_watts": direct_watts,
            "power_consumption_derived_watts": derived_watts,
        }

    def read_temperature(
        self,
        *,
        thermal_root: Path = Path("/sys/class/thermal/thermal_zone0"),
    ) -> SensorReading:
        """Read thermal sensor; reject virtualized constant-zero dummy values."""
        temp_path = thermal_root / "temp"
        if not temp_path.is_file():
            return SensorReading(
                name="temperature_celsius",
                status=SensorStatus.UNAVAILABLE,
                value=None,
                unit="C",
                source_path=str(temp_path),
                note="Thermal zone sysfs file does not exist.",
            )
        raw = temp_path.read_text(encoding="utf-8", errors="replace").strip()
        if not raw.lstrip("-").isdigit() or int(raw) <= 0:
            return SensorReading(
                name="temperature_celsius",
                status=SensorStatus.UNAVAILABLE,
                value=None,
                unit="C",
                source_path=str(temp_path),
                note=(
                    f"Thermal zone reports raw={raw!r} (virtualized placeholder in Crostini); "
                    "marked UNAVAILABLE instead of displaying fake 0C."
                ),
            )
        c_val = str((Decimal(int(raw)) / Decimal(1000)).quantize(Decimal("0.1")))
        return SensorReading(
            name="temperature_celsius",
            status=SensorStatus.AVAILABLE,
            value=c_val,
            unit="C",
            source_path=str(temp_path),
            note="Physical thermal zone reading.",
        )

    def read_gpu_metrics(self, *, drm_root: Path = Path("/sys/class/drm")) -> SensorReading:
        """Check DRM sysfs; report UNSUPPORTED when no GPU utilization/VRAM is exposed."""
        has_card = any(p.name.startswith("card") for p in drm_root.glob("card*")) if drm_root.is_dir() else False
        if not has_card:
            return SensorReading(
                name="gpu_utilization_and_vram",
                status=SensorStatus.UNSUPPORTED,
                value=None,
                unit="% / MiB",
                source_path=str(drm_root),
                note="No GPU card or VRAM counters exposed in /sys/class/drm.",
            )
        return SensorReading(
            name="gpu_utilization_and_vram",
            status=SensorStatus.UNAVAILABLE,
            value=None,
            unit="% / MiB",
            source_path=str(drm_root),
            note="DRM card present but vendor utilization/VRAM counters are not exposed.",
        )

    def poll_snapshot(self, *, panel_enabled: bool = False) -> dict[str, Any]:
        """Collect read-only snapshot; distinguish Crostini interior vs outer ChromeOS host."""
        meminfo_data: dict[str, int] = {}
        meminfo_path = Path("/proc/meminfo")
        if meminfo_path.is_file():
            for line in meminfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    meminfo_data[parts[0].rstrip(":")] = int(parts[1])

        total_kib = meminfo_data.get("MemTotal", 0)
        avail_kib = meminfo_data.get("MemAvailable", 0)
        used_kib = max(0, total_kib - avail_kib)

        st = os.statvfs(self._workspace_dir)
        disk_total_mib = (st.f_blocks * st.f_frsize) // (1024 * 1024)
        disk_free_mib = (st.f_bavail * st.f_frsize) // (1024 * 1024)
        disk_used_mib = max(0, disk_total_mib - disk_free_mib)

        power_sep = self.read_power_and_battery_separated()
        temp_reading = self.read_temperature()
        gpu_reading = self.read_gpu_metrics()
        outer_host = SensorReading(
            name="outer_chromeos_host_state",
            status=SensorStatus.UNVERIFIED_OUTSIDE_CROSTINI_BOUNDARY,
            value=None,
            unit="N/A",
            source_path="outside_crostini_vm_boundary",
            note=(
                "Outer ChromeOS host settings, physical NICs, and hypervisor internals "
                "cannot be inspected from inside Crostini and are explicitly UNVERIFIED."
            ),
        )

        return {
            "user_monitoring_panel_enabled": panel_enabled,
            "cpu_logical_cores": SensorReading(
                name="cpu_logical_cores",
                status=SensorStatus.AVAILABLE,
                value=os.cpu_count() or 1,
                unit="cores",
                source_path="/proc/cpuinfo",
                note="Observable logical vCPUs inside Crostini guest.",
            ).to_dict(),
            "system_memory_mib": SensorReading(
                name="system_memory_mib",
                status=SensorStatus.AVAILABLE,
                value={
                    "total_mib": total_kib // 1024,
                    "used_mib": used_kib // 1024,
                    "available_mib": avail_kib // 1024,
                },
                unit="MiB",
                source_path="/proc/meminfo",
                note="Crostini container/VM memory state.",
            ).to_dict(),
            "storage_mib": SensorReading(
                name="storage_mib",
                status=SensorStatus.AVAILABLE,
                value={
                    "total_mib": disk_total_mib,
                    "used_mib": disk_used_mib,
                    "free_mib": disk_free_mib,
                },
                unit="MiB",
                source_path="os.statvfs",
                note="Workspace filesystem usage and free capacity.",
            ).to_dict(),
            "power_and_battery": {k: v.to_dict() for k, v in power_sep.items()},
            "temperature": temp_reading.to_dict(),
            "gpu": gpu_reading.to_dict(),
            "outer_chromeos_host_boundary": outer_host.to_dict(),
        }
