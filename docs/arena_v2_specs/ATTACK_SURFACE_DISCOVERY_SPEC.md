# ATTACK_SURFACE_DISCOVERY_SPEC.md
## THUNDERHALL (サンダーホール) — 自律アタックサーフェス探索エンジン仕様書

### 1. 概要
`src/arena/ai_vuln_engine.ts` (`discoverAttackSurfaces()`) により、公開/内部エンドポイント、SSEストリーム、Python IPC ブリッジ、ローカル音声合成バインディング等の攻撃対象面（Attack Surface）を自動列挙する。

### 2. 必須スキーマ
すべてのエントリは以下の構造を厳守する：
- `surface_id`: 一意識別子 (`SURF-HTTP-PUBLIC-LOGIN` 等)
- `surface_type`: `HTTP_API` | `SSE_STREAM` | `PYTHON_SUBPROCESS_IPC` | `FILE_VAULT` | `LOCAL_VOICEVOX_IPC` | `SIMULATED_BOT_INGRESS`
- `exposure_level`: `PUBLIC_UNAUTHENTICATED` | `AUTHENTICATED_USER` | `PRIVILEGED_ADMIN` | `LOCALHOST_ONLY` | `ISOLATED_SIMULATION`
- `auth_required`: 真偽値
- `privilege_level`: 要求ロール (`NONE`, `viewer+`, `operator+`, `admin`, `LOOPBACK_127_0_0_1`)
- `input_vectors`: 入力パラメータ群
- `trust_boundary`: 対応する信頼境界ID (`TB-01`〜`TB-04`)
- `reachability`: `REACHABLE_LOCAL` | `REACHABLE_AUTHENTICATED` | `ISOLATED_SANDBOX` | `UNREACHABLE_EXTERNAL`
- `evidence`: 実装ファイルおよび行番号エビデンス
