# SECURITY_TEST_SCENARIOS.md — 再現可能セキュリティテストシナリオ設計書

> **ステータス**: Phase 1（シナリオ設計完了 / 実装未着手・承認待ち）

---

## 1. 実装済み・未実装・推定・未検証の区分

| 区分 | 内容 |
| :--- | :--- |
| **1. 証拠によって確認済み（実装済み）** | `/home/harukiy1225/MK1Ai-main` には、`scripts/verify_1m_packets_airgap.py`（正常通信100万件＋攻撃通信100万件のDPI・キルスイッチ検証）、`scripts/verify_1_6tbps_zero_trust.py`（10カテゴリ×10,000件のレッドチーム検証）、およびC言語単体テスト（`tests/test_mk1_tunnel.c`, `test_mk1_memory_guard.c`, `test_mk1_path_trust.c`）が存在する。 |
| **2. 静的解析による候補（未実装）** | AegisLab の統一シナリオスキーマ（14必須属性）、OSバージョン紐付け、XDPとDPIの判定差検証シナリオ、隔離違反・マスキング失敗注入シナリオは `/home/harukiy1225/テストツール` 内に**未実装**である。 |
| **3. 推定または設計上の懸念** | 大量シナリオ実行時に全テストケースのパケットダンプを保存するとディスク（空き1.4GiB）が即座に枯渇するため、乱数シード (`seed`) と生成パラメータによる決定論的再生成方式＋失敗ケースのみ上限付き標本保存とする設計が必須である。 |
| **4. 未検証** | 実XDPプログラムをアタッチした状態での「XDPと後段DPIの判定差」実測テストは、現ホストに `clang`/`bpftool` が未導入のため**未検証**である。 |

---

## 2. シナリオ共通データスキーマ（14必須フィールド）

すべてのセキュリティテストシナリオは以下の14項目を必須定義とし、1項目でも欠落しているシナリオはロード時にスキーマエラーとして拒否する。

```json
{
  "test_id": "SCN-DPI-001",
  "purpose": "マルチエンコーディング（UTF-16LE/BE, 二重URLエンコード, Nullバイト混入）によるDPIバイパス耐性とFail-Closed動作の検証",
  "preconditions": [
    "隔離環境または合成データ検証モードが有効であること",
    "外部ネットワーク通信が遮断されていること"
  ],
  "target_component": "DPI Verification Engine / airgap_ai_defender.inspect_packet_pipeline",
  "test_data_spec": {
    "generator": "deterministic_synthetic_payload_v1",
    "sample_count": "10000",
    "input_sha256": "<実行時に算出・記録>"
  },
  "execution_conditions": {
    "mode": "VIRTUAL_SIM | DRY_RUN | ISOLATED_REAL",
    "timeout_ms_per_item": 50,
    "max_memory_mb": 256
  },
  "expected_result": {
    "malicious_blocked_ratio": "1.000000",
    "benign_false_positive_count": "0",
    "on_timeout_or_exception": "FAIL_CLOSED_BLOCK"
  },
  "actual_result": null,
  "pass_criteria": "全悪性ベクタがBLOCK/QUARANTINE判定され、かつ例外・タイムアウト発生時に1件もALLOW（Fail-Open）されないこと",
  "stop_conditions": [
    "Fail-Open（未判定通過）が1件でも発生した場合",
    "メモリ使用量が上限 (256MB) の90%を超過した場合",
    "ユーザーの停止要求を受信した場合"
  ],
  "reproduction_seed": "202610290001",
  "os_and_image_version": {
    "guest_os": "mk1ai-secure-linux",
    "image_version": "unbuilt-spec-v1",
    "host_kernel": "6.6.147-09648-g97ef00d8a343"
  },
  "constraints": [
    "第三者システム宛ての送信は厳禁（純粋バイト列または隔離veth限定）",
    "ホスト空きディスク500MiB未満では実行不可"
  ],
  "evidence_refs": []
}
```

---

## 3. 標準搭載する19カテゴリのテストシナリオ一覧

| シナリオID | カテゴリ | 検証内容 | 合格条件 (`PASS`) | 停止条件 |
| :--- | :--- | :--- | :--- | :--- |
| `SCN-INP-001` | 異常な入力 | 空バイト列、超長大文字列、制御文字、非印字バイト列の注入 | クラッシュせず明示的拒否 (`REJECT`/`BLOCK`) | 未捕捉例外またはメモリリーク |
| `SCN-HDR-002` | 不正形式パケットヘッダー | IPv4/IPv6 バージョン不一致、IHL $< 5$、TCP Data Offset 不正、不正フラグ組み合わせ | パーサが境界外参照せず `DROP` 判定 | バッファオーバーリードまたは `ALLOW` |
| `SCN-LEN-003` | 長さフィールド不整合 | IP Total Length と実フレーム長（短小切詰め / 65,600B超ジャンボ）の不一致 | 長さ不整合検出により即時 `BLOCK` | 切り詰め部分の未検査通過 |
| `SCN-BND-004` | プロトコル境界テスト | MTU境界（1500B/65535B）、フラグメント分割、チャンク境界またぎの攻撃文字列 | 再構成または境界検査で100%検出 | 分割によるシグネチャ回避成功 |
| `SCN-ENC-005` | 文字コード・正規化不一致 | UTF-8 Overlong、UTF-16LE/BE、NFKC正規化前後の `<script>` / `powershell` 難読化 | 正規化後に検査され100% `BLOCK` | 正規化前の素通り |
| `SCN-AUT-006` | 認証・認可の検証 | 未署名トークン、権限不足ロール、改ざんHMACによる特権API呼び出し | HTTP 401/403 または `PermissionDenied` | 未認可操作の実行成功 |
| `SCN-SES-007` | セッション管理 | セッションID固定化、期限切れトークン、ラチェット鍵の世代不一致 | 即時セッション無効化・再認証要求 | 旧世代鍵での復号・受理 |
| `SCN-RPL-008` | リプレイ耐性 | 同一Nonce・同一シーケンス番号・過去の有効署名付きメッセージの再送 | リプレイウィンドウ検査により100%拒否 | 再送メッセージの二重受理 |
| `SCN-RES-009` | リソース枯渇耐性 | 大量同時接続モデル、高負荷バッチ投入時のメモリ・CPU・キュー上限動作 | 上限でバックプレッシャまたは安全停止が作動しOOMしない | ホストOOMまたはハングアップ |
| `SCN-TMO-010` | タイムアウト | DPI/AI推論・外部検証の応答遅延を模擬注入 | タイムアウト時に **Fail-Closed（遮断）** となること | タイムアウト時の素通り（Fail-Open） |
| `SCN-DPI-011` | DPIの誤検知と見逃し | 正常トラフィック標本（HTTP/JSON/TLS/DNS等）と攻撃標本の混合投入 | 誤検知率（FP）および見逃し率（FN）が基準値（0件）を満たす | FPまたはFNの発生 |
| `SCN-XDP-012` | XDP/eBPFと後段DPIの判定差 | L3/L4 XDP フィルタと L7 DPI の判定境界ケース（XDP_PASS かつ DPI_BLOCK 等）の整合性確認 | 期待通り段階的防御が機能し、XDP未導入時は「未検証」と明示される | XDP未稼働を稼働済みと偽装 |
| `SCN-FCL-013` | Fail-Open と Fail-Closed | 検査エンジン内部で意図的に例外 (`RuntimeError`) を発生させる | 100% **Fail-Closed**（通信遮断・安全停止）に倒れること | 例外時に通信が通過する |
| `SCN-LOG-014` | ログ欠落・記録不能 | ログ出力先の容量上限到達・書き込み権限剥奪を模擬 | ログ記録不能を検知した瞬間にテスト実行自体を安全停止する | ログなしのままテストが継続する |
| `SCN-ERR-015` | エラー処理 | 破損設定ファイル、不正な数値文字列（`"1e16"`, `"-5"`, `"NaN"`）の入力 | 正確なエラーコードで拒否し内部状態を汚染しない | 不正値の暗黙丸め・状態破壊 |
| `SCN-OSC-016` | OSごとの互換性 | 各ゲストOS記述子に対するプリフライト検証と互換性チェック | 未対応・リソース不足OSが実行前に確実にブロックされる | 非互換OSの強行起動 |
| `SCN-RST-017` | 再起動と復元 | テスト実行中または配信設定後のプロセス再起動模擬 | 再起動後、実パケット送信やライブ配信が **自動的にOFF** で立ち上がる | 再起動後に実送信・配信が自動再開 |
| `SCN-ISO-018` | 隔離違反の検知 | サンドボックス内から許可外IP（例: `8.8.8.8`）へのソケット接続試行 | `Isolation & Safety Controller` が即時ブロック・緊急停止・証拠保全 | 外部へのパケット送出成功 |
| `SCN-RED-019` | 秘密情報の漏えい検査 | ダミーのIPv4/IPv6、MAC、ストリームキー、秘密鍵、ユーザー名をイベントログ・オーバーレイに注入 | 公開用出力・プレビュー・レポートから100%マスクされ、失敗時は配信停止 | 平文での画面表示またはログ露出 |
