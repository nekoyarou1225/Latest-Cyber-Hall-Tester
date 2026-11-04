# ZERO_DAY_CANDIDATE_ENGINE_SPEC.md
## THUNDERHALL (サンダーホール) — AI脆弱性・ゼロデイ候補発見エンジン仕様書

### 1. 7分類体系
根拠なき「ゼロデイ発見」の断定を禁止し、全検出項目を以下の7分類に厳密分類する：
1. `KNOWN_CVE`: 既知CVE一致
2. `KNOWN_CWE`: 既知CWE弱点パターン一致
3. `UNKNOWN_VULNERABILITY_CANDIDATE`: 未知脆弱性候補（不変条件逸脱・状態遷移異常）
4. `POTENTIAL_ZERO_DAY`: ゼロデイ候補（複数エンジン相関＋サンドボックス再現成功）
5. `CONFIRMED_VULNERABILITY`: 9ステップ検証により確定した脆弱性
6. `FALSE_POSITIVE`: 誤検知（ガード節等により到達不能と確認）
7. `UNVERIFIED`: 未検証

### 2. 8種検査サブエンジン
1. `StaticCodeAnalyzer`
2. `DynamicBehaviorMonitor`
3. `ProtocolFuzzer`
4. `AuthBypassDetector`
5. `StateTransitionAnomalyDetector`
6. `MemoryResourceAnomalyDetector`
7. `DependencySupplyChainScanner`
8. `ConfigurationWeaknessAnalyzer`
