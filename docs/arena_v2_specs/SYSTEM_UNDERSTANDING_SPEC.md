# SYSTEM_UNDERSTANDING_SPEC.md
## THUNDERHALL (サンダーホール) — 24次元システム理解エンジン仕様書

### 1. 概要
`src/arena/ai_vuln_engine.ts` (`runSystemUnderstandingEngine()`) にて実装された、24項目のシステム構造・信頼境界・観測可能性を自律解析するエンジン。

### 2. 24次元観測項目と `UNKNOWN` 明示ポリシー
推測による補完を厳禁とし、非特権ユーザ空間から直接観測できないカーネル空間・物理ルーティングテーブル等は `status: "UNKNOWN"` として明示する。

- **SYS-01〜SYS-21**: OS / CPU / Memory / Listening Ports / HTTP Routes / Auth Session / RBAC & 32-Plan License / Trust Boundary / Secrets / Audit Log / Crypto / Dependencies / Static Analysis / Fuzzing / Supply Chain (`OBSERVED`)
- **SYS-22**: Network Interface & Routing (`UNKNOWN` — 非特権コンテナのためカーネル FIB 直接参照不可)
- **SYS-23**: Firewall / eBPF / XDP Kernel State (`UNKNOWN` — `CAP_BPF` 非保持のため Dry-Run Manifest のみ)
- **SYS-24**: Container / Sandbox Isolation (`OBSERVED`)

### 3. 出力モデル
1. **System Inventory** (`dimensions`: 24件)
2. **Architecture Graph** (`architecture_graph`: ノード・エッジ・プロトコル・暗号化有無)
3. **Trust Boundary Map** (`trust_boundary_map`: 境界ID・横断コントロール・リスク水準)
