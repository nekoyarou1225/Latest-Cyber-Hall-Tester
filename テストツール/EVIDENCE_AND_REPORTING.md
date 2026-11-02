# EVIDENCE_AND_REPORTING.md — 記録・レポート・監査証拠管理設計書

> **ステータス**: Phase 1（証拠管理・4分類/4区分レポート設計完了 / 実装未着手・承認待ち）

---

## 1. 実装済み・未実装・推定・未検証の区分

| 区分 | 内容 |
| :--- | :--- |
| **1. 証拠によって確認済み（実装済み）** | `MK1Ai-main` には `BENCHMARK_REPORT.md`、`MK1AI_TECHNICAL_SECURITY_REPORT.md`、`docs/ASSURANCE_GAPS.md`、`scripts/sign_release.py`、`scripts/verify_release.py` が存在し、既存のベンチマーク記録やギャップ分析ドキュメントが確認できる。 |
| **2. 静的解析による候補（未実装）** | AegisLab の16必須項目バンドルスキーマ、`PASS`/`FAIL`/`INCONCLUSIVE`/`NOT TESTED` 自動分類器、4区分（確認済み/静的解析候補/推定・懸念/未検証）強制テンプレート、および誇張表現ブロック機構は `/home/harukiy1225/テストツール` 内に**未実装**である。 |
| **3. 推定または設計上の懸念** | 証拠ログを無制限に出力すると現ホストの空きディスク（1.4 GiB）を圧迫するため、1テストあたりのログ上限（例: 10 MB）とサマリー中心の構造化保存が必須である。 |
| **4. 未検証** | テストレポート自動生成からマスキング検証・ハッシュ署名出力までの一貫パイプラインは**未検証**である。 |

---

## 2. テスト結果の4分類（Verdict Classification）定義

すべてのテストシナリオおよびモジュール検証結果は、必ず以下の4つのいずれかに分類し、失敗や未実行を隠蔽したり曖昧に `PASS` へ丸めたりすることを禁止する。

| 判定コード | 厳密な適用基準 |
| :--- | :--- |
| **`PASS`** | 事前に定義された合格条件（Pass Criteria）のすべてを、**実行時の実測証拠（ログ、カウンター、ハッシュ、状態確認）によって満たした**場合のみ付与。 |
| **`FAIL`** | 合格条件を1つでも満たさなかった場合、Fail-Open が発生した場合、隔離違反・整合性違反が発生した場合、または安全停止に追い込まれた場合に付与。 |
| **`INCONCLUSIVE`** | テストは実行されたが、環境ノイズ・タイムアウト・センサー未提供・途中中断等により合格/不合格を決定づける証拠が不足している、または結果に矛盾がある場合に付与。 |
| **`NOT TESTED`** | 初期OFFのまま未実行である場合、前提条件（ハイパーバイザ、`clang`/`bpftool`、空き容量、ユーザー承認など）を満たしておらず実行を見送った場合、またはドライランのみの場合に付与。 |

---

## 3. 各テストについて保存する16の必須情報スキーマ

`Telemetry & Evidence Manager`（Module 19）は、各テスト実行ごとに以下の16項目を欠落なく記録した `evidence-bundle.json` を生成する。

```json
{
  "1_test_id": "TEST-20261029-0001",
  "2_timestamps": {
    "started_at_iso8601": "2026-10-29T15:30:00+09:00",
    "ended_at_iso8601": "2026-10-29T15:30:05+09:00",
    "monotonic_duration_ns": "5000123456"
  },
  "3_target_program_version": {
    "aegislab_version": "0.1.0-phase2",
    "mk1ai_ref_sha256": "<対象スクリプト群のSHA-256マニフェスト>"
  },
  "4_os_and_image_version": {
    "selected_guest_os": "mk1ai-secure-linux",
    "image_version": "unbuilt-or-verified-tag",
    "image_manifest_sha256": null,
    "host_os": "Debian GNU/Linux 13 (trixie)",
    "host_kernel": "6.6.147-09648-g97ef00d8a343"
  },
  "5_vm_configuration": {
    "backend": "synthetic-dryrun | linux-ns | kvm-qemu",
    "vcpu_limit": 1,
    "memory_limit_mb": 256,
    "network_isolation": "DEFAULT_DENY_AIRGAP"
  },
  "6_environment_info": {
    "cpu_model": "Intel(R) N100 (4 cores)",
    "host_ram_total_mb": 2662,
    "host_ram_available_mb": 565,
    "host_disk_free_mb": 1433
  },
  "7_test_scenario": {
    "scenario_id": "SCN-DPI-011",
    "purpose": "DPI誤検知・見逃し検証"
  },
  "8_config_parameters": {
    "execution_mode": "VIRTUAL_SIM",
    "batch_size": 1000
  },
  "9_random_seed": "202610290001",
  "10_input_data_hash": "sha256:...",
  "11_target_values": {
    "target_packets": "10000000000000000",
    "target_virtual_bots": "10000000000000000",
    "theoretical_rate_gbps": "100000000000000000"
  },
  "12_measured_values": {
    "individually_processed_packets": "0",
    "modeled_statistical_packets": "10000000000000000",
    "empirical_network_rate_bps": null,
    "measurement_status": "SIMULATED_ONLY_NOT_EMPIRICALLY_MEASURED"
  },
  "13_audit_logs_summary": {
    "log_entry_count": 42,
    "head_chain_sha256": "sha256:...",
    "tail_chain_sha256": "sha256:...",
    "redaction_applied": true
  },
  "14_verdict": "PASS | FAIL | INCONCLUSIVE | NOT TESTED",
  "15_reproduction_conditions": {
    "command": "python3 -m aegislab.cli run --scenario SCN-DPI-011 --seed 202610290001 --mode VIRTUAL_SIM",
    "required_env": "Python 3.13+"
  },
  "16_unverified_items": [
    "実XDPカーネルプログラムのロード・アタッチ（Stage 5〜9）は未検証",
    "物理10Gbps NIC上での実測は未実施（理論モデルおよびシミュレーションのみ）"
  ]
}
```

---

## 4. 報告書の必須4区分テンプレートと誇張防止ガード

生成されるすべてのレポート（Markdown / JSON / UI完了レポートシーン）は、必ず以下の4つの章を独立して設けなければならない。

1. **第1区分：証拠によって確認済み（Confirmed by Empirical Evidence）**
   - 実際に実行・計測され、ログ・ハッシュ・出力値によって裏付けられた事実のみを記載。
2. **第2区分：静的解析による候補（Candidates Identified by Static Analysis）**
   - コード検査・設定検査・スキーマ検査によって確認された構造や潜在的リスク候補。実行証跡とは区別する。
3. **第3区分：推定または設計上の懸念（Estimations & Architectural Concerns）**
   - 数理モデル計算値（例：$10^{16}$ ボットの理論レート $10^{17}\text{ Gbps}$ や電圧×電流からの推定電力W）、およびハードウェア制約に関する懸念事項。
4. **第4区分：未検証（Unverified / Not Tested）**
   - 権限不足、ツール未導入、初期OFF、または承認未取得により実行していない項目を隠さず列挙する。

### 誇張・虚偽主張の禁止バリデータ
`Test Report Generator`（Module 20）は、出力テキスト中に「完全な安全性が証明された」「脆弱性ゼロ」「100%絶対に破られない」「実測100京bps達成」等の根拠なき誇張表現や、シミュレーション値を実測値と混同する表現が含まれていないかを検査し、検出時は生成を拒否する。
