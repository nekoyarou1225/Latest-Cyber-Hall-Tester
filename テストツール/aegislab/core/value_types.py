"""Core value types, 5-way metric labels, 4-way verdicts, and scope tags."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any

MIN_COUNT_INT: int = 1
MAX_COUNT_INT: int = 10**16  # 1京 = 10,000,000,000,000,000
DECIMAL_INT_PATTERN = re.compile(r"^[0-9]+$")


class MetricCategory(str, Enum):
    """Mandatory 5-way distinction for rates, counts, and performance numbers."""

    THEORETICAL = "THEORETICAL"       # 理論値 (数学モデル上の計算値)
    SIMULATED = "SIMULATED"           # シミュレーション値 (モデル上の集計値)
    MEASURED = "MEASURED"             # 実測値 (実環境・実通信での測定値)
    UNMEASURABLE = "UNMEASURABLE"     # 測定不可 (物理限界超過またはセンサー不在)
    UNVERIFIED = "UNVERIFIED"         # 未検証 (未実行またはドライランのみ)


class Verdict(str, Enum):
    """Mandatory 4-way test result classification."""

    PASS = "PASS"                     # 合格条件を証拠で満たした
    FAIL = "FAIL"                     # 合格条件を満たさなかった
    INCONCLUSIVE = "INCONCLUSIVE"     # 証拠不足または結果に矛盾がある
    NOT_TESTED = "NOT TESTED"         # 未実行または実行条件を満たしていない


class FindingSection(str, Enum):
    """Mandatory 4-section distinction in reports."""

    CONFIRMED_BY_EVIDENCE = "CONFIRMED_BY_EVIDENCE"       # 1. 証拠によって確認済み
    STATIC_ANALYSIS_CANDIDATE = "STATIC_ANALYSIS_CANDIDATE"  # 2. 静的解析による候補
    ESTIMATION_OR_CONCERN = "ESTIMATION_OR_CONCERN"       # 3. 推定または設計上の懸念
    UNVERIFIED = "UNVERIFIED"                             # 4. 未検証


class ControlScope(str, Enum):
    """Distinguishes software-level guards from OS/virtualization enforcement."""

    APPLICATION_CONFIG_LOCK = "APPLICATION_CONFIG_LOCK"
    APPLICATION_THRESHOLD_GUARD = "APPLICATION_THRESHOLD_GUARD"
    OS_KERNEL_RESOURCE_ENFORCEMENT = "OS_KERNEL_RESOURCE_ENFORCEMENT"
    OS_VIRTUALIZATION_ISOLATION = "OS_VIRTUALIZATION_ISOLATION"


class SystemState(str, Enum):
    """10 user-visible operational states required by Section 18."""

    UNCONFIGURED = "未設定"
    CONFIGURED = "設定済み"
    VERIFYING = "検証中"
    READY = "準備完了"
    RUNNING = "実行中"
    PAUSED = "一時停止"
    STOPPING = "停止中"
    COMPLETED = "完了"
    FAILED = "失敗"
    UNVERIFIED = "未検証"


def parse_exact_decimal_int(
    value: int | str,
    *,
    field_name: str,
    min_val: int = MIN_COUNT_INT,
    max_val: int = MAX_COUNT_INT,
) -> int:
    """Parse an integer or strict base-10 string without float rounding."""
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(
            f"{field_name}: float or bool is prohibited to prevent IEEE-754 precision loss"
        )
    if isinstance(value, str):
        if not DECIMAL_INT_PATTERN.fullmatch(value):
            raise ValueError(
                f"{field_name}: must be a strict base-10 digit string (got {value!r})"
            )
        if len(value) > 1 and value.startswith("0"):
            raise ValueError(f"{field_name}: leading zeros are not allowed")
        parsed = int(value, 10)
    elif isinstance(value, int):
        parsed = value
    else:
        raise TypeError(f"{field_name}: unsupported type {type(value).__name__}")

    if parsed < min_val or parsed > max_val:
        raise ValueError(
            f"{field_name}: value {parsed} out of allowed range [{min_val}, {max_val}]"
        )
    return parsed


def format_japanese_large_number(n: int) -> str:
    """Format an exact integer (up to 10^16+) with comma and Japanese unit breakdown."""
    if n < 0:
        raise ValueError("Negative numbers not supported for counter display")
    if n == 0:
        return "0"
    kei, rem = divmod(n, 10**16)
    cho, rem = divmod(rem, 10**12)
    oku, rem = divmod(rem, 10**8)
    man, one = divmod(rem, 10**4)
    parts: list[str] = []
    if kei:
        parts.append(f"{kei}京")
    if cho:
        parts.append(f"{cho}兆")
    if oku:
        parts.append(f"{oku}億")
    if man:
        parts.append(f"{man}万")
    if one:
        parts.append(f"{one}")
    return "".join(parts)


@dataclass(frozen=True)
class LabeledMetric:
    """Wrapper ensuring theoretical, simulated, and measured values never mix."""

    name: str
    category: MetricCategory
    value_str: str | None
    unit: str
    note: str
    verification_status: Verdict = Verdict.NOT_TESTED

    def __post_init__(self) -> None:
        if self.category == MetricCategory.MEASURED and self.value_str is not None:
            if self.verification_status != Verdict.PASS:
                raise ValueError(
                    "MEASURED metric with non-null value requires PASS verification_status"
                )
        if self.category in (MetricCategory.UNMEASURABLE, MetricCategory.UNVERIFIED):
            if self.value_str is not None:
                raise ValueError(
                    f"{self.category.value} metric must have value_str=None to prevent fake numbers"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "value_str": self.value_str,
            "unit": self.unit,
            "note": self.note,
            "verification_status": self.verification_status.value,
        }
