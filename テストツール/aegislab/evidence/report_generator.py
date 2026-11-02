"""Test Report Generator (Module 20).

Enforces:
- 4-way verdict classification: PASS, FAIL, INCONCLUSIVE, NOT TESTED.
- 4 mandatory report sections:
    1. 証拠によって確認済み (CONFIRMED_BY_EVIDENCE)
    2. 静的解析による候補 (STATIC_ANALYSIS_CANDIDATE)
    3. 推定または設計上の懸念 (ESTIMATION_OR_CONCERN)
    4. 未検証 (UNVERIFIED)
- Anti-exaggeration validator blocking unsubstantiated security claims,
  conflation of application config switches with OS isolation, or claims of
  100% universal PII detection from synthetic pattern tests.
- Mandatory Fail-Closed redaction via RedactionEngine on all public reports.
"""

from __future__ import annotations

import re
from typing import Any

from aegislab.core.value_types import Verdict
from aegislab.evidence.recorder import REQUIRED_16_EVIDENCE_KEYS
from aegislab.privacy.redactor import REDACTION_LIMITATION_DISCLOSURE, RedactionEngine


class ExaggeratedClaimError(ValueError):
    """Raised when a report contains prohibited exaggerated or misleading security claims."""


PROHIBITED_CLAIM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"完全な安全性|脆弱性ゼロ|100%\s*安全|絶対に破られない", re.IGNORECASE),
    re.compile(r"ソフト(?:ウェア)?スイッチ.*OS(?:レベル)?隔離を実証", re.IGNORECASE),
    re.compile(r"あらゆる個人情報を100%検出", re.IGNORECASE),
)


class ReportGenerator:
    """Generates reproducible, non-exaggerated, redacted 4-section Markdown reports."""

    def __init__(self, redactor: RedactionEngine) -> None:
        self._redactor = redactor

    @staticmethod
    def validate_no_exaggerated_claims(text: str) -> None:
        for pat in PROHIBITED_CLAIM_PATTERNS:
            if pat.search(text):
                raise ExaggeratedClaimError(
                    f"Prohibited exaggerated or misleading claim detected matching {pat.pattern!r}"
                )

    def generate_markdown_report(
        self,
        *,
        evidence_bundle: dict[str, Any],
        confirmed_by_evidence: list[str],
        static_analysis_candidates: list[str],
        estimations_or_concerns: list[str],
        unverified_items: list[str],
        capability_matrix: dict[str, Verdict],
    ) -> str:
        """Render a sanitized Markdown report with all 4 required sections and scope disclaimers."""
        for k in REQUIRED_16_EVIDENCE_KEYS:
            if k not in evidence_bundle:
                raise ValueError(f"Evidence bundle missing required field: {k}")

        if not confirmed_by_evidence or not unverified_items:
            raise ValueError(
                "Both confirmed_by_evidence and unverified_items must be non-empty"
            )

        sanitized_bundle = self._redactor.redact_structure(evidence_bundle)
        c_list = [self._redactor.redact_text(x) for x in confirmed_by_evidence]
        s_list = [self._redactor.redact_text(x) for x in static_analysis_candidates]
        e_list = [self._redactor.redact_text(x) for x in estimations_or_concerns]
        u_list = [self._redactor.redact_text(x) for x in unverified_items]

        cap_lines: list[str] = []
        for cap_name, cap_verdict in capability_matrix.items():
            safe_name = self._redactor.redact_text(cap_name)
            cap_lines.append(f"| `{safe_name}` | **`{cap_verdict.value}`** |")

        lines: list[str] = [
            f"# AegisLab Security Verification Report — `{sanitized_bundle['test_id']}`",
            "",
            f"- **総合判定 (Overall Verdict)**: **`{sanitized_bundle['verdict']}`**",
            f"- **対象OS / イメージ状態**: `{sanitized_bundle['os_and_image_version']}`",
            f"- **再現用乱数シード (Seed)**: `{sanitized_bundle['random_seed']}`",
            f"- **入力データハッシュ**: `{sanitized_bundle['input_data_hash']}`",
            "",
            "## 0. 検証スコープ・安全ロック・マスキング限界に関する重要事項",
            "",
            "- **安全ロックの検証範囲**: Phase 2A で検証したのは **アプリケーション内の設定スイッチロック (`APPLICATION_CONFIG_LOCK`) およびアプリ内閾値チェック (`APPLICATION_THRESHOLD_GUARD`)** のみです。OS・カーネル・仮想化レベルの強制隔離 (`OS_VIRTUALIZATION_ISOLATION`) や実ネットワーク遮断は **未実行 (`NOT TESTED`)** であり、ソフトスイッチがOFFであることだけを根拠にOS隔離や実通信阻止が実証されたとは主張しません。",
            f"- **個人情報マスキングの検証範囲**: {REDACTION_LIMITATION_DISCLOSURE}",
            "- **Crostini 境界外の扱い**: 外側の ChromeOS ホストOS・物理NIC・ハイパーバイザ内部状態は Crostini コンテナ内から直接観測できないため **`UNVERIFIED_OUTSIDE_CROSTINI_BOUNDARY`（未確認）** として区別しています。",
            "",
            "## 1. 証拠によって確認済み (Confirmed by Empirical Evidence)",
            "",
            *[f"- {item}" for item in c_list],
            "",
            "## 2. 静的解析による候補 (Candidates Identified by Static Analysis)",
            "",
            *[f"- {item}" for item in s_list],
            "",
            "## 3. 推定または設計上の懸念 (Estimations & Architectural Concerns)",
            "",
            *[f"- {item}" for item in e_list],
            "",
            "## 4. 未検証 (Unverified / `NOT TESTED`)",
            "",
            *[f"- {item}" for item in u_list],
            "",
            "## 5. 機能別検証ステータスマトリクス (`PASS` / `FAIL` / `INCONCLUSIVE` / `NOT TESTED`)",
            "",
            "| 検証項目 / 機能 | 判定ステータス |",
            "| :--- | :--- |",
            *cap_lines,
            "",
        ]

        report_md = "\n".join(lines)
        self.validate_no_exaggerated_claims(report_md)
        # Final pass through redactor to guarantee Fail-Closed safety
        return self._redactor.redact_text(report_md)
