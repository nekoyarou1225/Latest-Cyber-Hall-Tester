# サンダーホール（THUNDERHALL）— プレミアム・セキュリティ・テスター

**サンダーホール（THUNDERHALL）** は、1京回（$10^{16}$）規模のBigIntパケット生成シミュレーション、Outer/Inner二層ハニーポット管理、Ed25519オフライン公開鍵ライセンス検証、2名認証済み管理者によるQuorum緊急遮断（Kill Switch）、およびSHA-256改ざん検知ハッシュ連鎖監査証跡を統合したセキュリティ検証プラットフォームです。

---

## 1. 起動方法とネットワークバインド設定（PART 2.1）

```bash
# 開発サーバー起動（デフォルトポート: 3000）
npm run dev

# ローカル単体環境でループバック (127.0.0.1) のみに厳格バインドする場合
BIND_HOST=127.0.0.1 PORT=3000 npm run dev
```

* エントリーポイント: `/server.ts`（Express API + SSE + `/index.html` 配信）
* 初期起動時の契約プラン: **`general.PLUS`（サンダーホール PLUS — 一般）**（1日1時間枠、ハニーポット最大2台、CORE保護100%常時有効）

---

## 2. 認証・ロールベース認可（RBAC）・CSRF保護（PART 2.1）

すべての管理・状態変更APIには **セッション認証 (`X-Session-Token` または `HttpOnly; SameSite=Strict` Cookie)**、**5段階ロール認可 (RBAC)**、および **CSRFトークン (`X-CSRF-Token`)** が強制されます。ログイン時にはセッションIDが毎回再生成され、セッション固定攻撃（Session Fixation）を防止します。

| ユーザーID | ロール (`UserRole`) | 認可範囲 | 用途 |
|---|---|---|---|
| `admin-alice` | `admin` | 全32プラン・ハニーポット・Quorum承認A・ZIP出力 | 最高セキュリティ管理官（Quorum署名官1） |
| `admin-bob` | `admin` | 全32プラン・ハニーポット・Quorum承認B・ZIP出力 | 暗号監査管理官（Quorum署名官2） |
| `group-chief` | `group_member` | 全区分（`group.*` 含む）・グループ管理 | サンダーホール特別作戦班 |
| `research-lead` | `researcher` | `general.*`, `research.*`・カスタムOS・テスト実行 | 先端セキュリティ研究所 |
| `biz-operator` | `business_operator` | `general.*`, `business.*`・ハニーポット運用 | 企業SOC運用オペレーター |
| `general-user` | `general_user` | `general.PLUS` 基本操作のみ（管理APIは `403` 遮断） | 一般開発者アカウント |

---

## 3. 32段階プラン体系とオフライン署名検証（PART 2.2 & PART 5）

* **4つの契約区分 × 8段階プラン（計32プラン）**:
  * 契約区分: `general`（一般）、`business`（業務用）、`research`（研究機関用）、`group`（サンダーホールグループ専用）
  * プラン識別子: `PLUS`, `PLUS PRO`, `PLUS PRO MAX`, `PRO`, `PRO MAX`, `Ultra`, `Ultra PRO`, `Ultra MAX`
* **署名鍵と検証鍵の分離**:
  * 秘密鍵は隔離された `IsolatedOfflineLicenseAuthorityVault` 内で管理され、ランタイム検証器（`verifyLicenseWithPublicKeyOnly`）は公開鍵（`AUTHORITY_PUBLIC_KEY_PEM`）のみを使用して署名を検証します。
* **4種類のハニーポット上限の透明な表示・計算**:
  * `license_limit`（プラン上限: 2〜256台）
  * `hardware_safe_limit`（実機空きRAMからの安全上限）
  * `admin_policy_limit`（管理者ポリシー上限: デフォルト256台）
  * `effective_max_honeypots` = $\min(\text{license\_limit}, \text{hardware\_safe\_limit}, \text{admin\_policy\_limit})$
* **CORE保護不変条件（Invariant）**:
  * ライセンスが期限切れまたは失効（CRL）した場合、自動的に `general.PLUS` へ安全降格しますが、**CORE隔離・基本的攻撃検知・緊急停止（Kill Switch）は100%常時有効**に維持されます。

---

## 4. Quorum（2名承認）緊急遮断ゲート（PART 2.3）

* クライアントから送信された自己申告の `admin_id` 文字列によるなりすましは `403 Forbidden` で遮断されます。
* 必ず **異なる2名の認証済み管理者アカウント**（例: `admin-alice` と `admin-bob`）それぞれのセッションからEd25519電子署名を行う必要があります。
* 同一管理者による2回目の承認は `409 Conflict` で拒否されます。
* 9段階のライフサイクル状態（`REQUESTED` → `APPROVAL_PENDING` → `APPROVED` / `REJECTED` → `EXECUTION_PENDING` → `EXECUTED` / `FAILED` → `VERIFICATION_PENDING` → `VERIFIED`）と有効期限（TTL）、リプレイ攻撃防止を実装しています。

---

## 5. 実機動作（REAL_EXECUTION）とシミュレーション（SIMULATED）の境界（PART 4）

| 機能モジュール | 区分 | 証拠分類 (`evidence_class`) | 内容 |
|---|---|---|---|
| ホストリソース監視 (SafetyGuard) | 実動作 | `VERIFIED_BY_EXECUTION` | `/proc/meminfo`, `process.memoryUsage().rss`, `fs.statfsSync` の実測 |
| 14カテゴリ機密マスキング | 実動作 | `VERIFIED_BY_EXECUTION` | クレジットカード・秘密鍵・OAuthトークン等の実文字列Fail-Closed置換 |
| Ed25519ライセンス＆Quorum署名 | 実動作 | `VERIFIED_BY_EXECUTION` | Node `crypto` Ed25519署名・公開鍵検証・単調増加カウンタ強制 |
| Read-Onlyファイル検査＆SHA-256 | 実動作 | `VERIFIED_BY_EXECUTION` | 実ファイルのSHA-256算出・パストラバーサル/Symlink遮断 |
| Python検証スイート実行 | 実動作 | `TEST_EXECUTED` | `python3 -B` サブプロセスによる実ユニットテスト実行 |
| 1〜1京回パケット生成＆ボット計算 | シミュレーション | `SIMULATED` | 64bit超 `BigInt` によるメモリ内厳密算術計数（外部パケット送信0バイト） |
| DPI / XDP / nftables 検証 | シミュレーション | `SIMULATED` | ホストカーネル設定を変更しない安全なDry-Runポリシー検証 |
| YouTube配信スタジオ (Fake Ingest) | シミュレーション | `SIMULATED` | 隔離された仮想シンクへのテスト信号送出（外部RTMP送信なし） |

---

## 6. 自動回帰テストの実行方法（PART 7）

```bash
# 1. TypeScript APIセキュリティ・32プラン・Quorum・監査チェーン包括検証 (66項目)
npx tsx tests/test_ui_and_api_buttons.ts

# 2. MK1Ai 製品化Pythonユニットテストスイート (7テスト / 17サブテスト)
python3 -B tests/test_mk1ai_productization.py -v

# 3. Phase 2A 保護ベースライン＆マニフェスト完全性検証スイート (15テスト)
PYTHONPATH=".:テストツール" python3 -B テストツール/tests/test_phase2a_suite.py -v
```