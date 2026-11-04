# TELEMETRY_SCORE_SPEC.md
## THUNDERHALL (サンダーホール) — 脅威スコア・通信テレメトリ完全分離仕様書

### 1. 設計原則
脅威スコア（0〜100の正規化リスク指標）と通信量テレメトリ（物理・仮想トラフィック計測値）を混同せず、独立したデータ構造およびUIパネル（Zone 1 上段/中段）として完全分離表示する。

### 2. 脅威スコア 5指標 (`SeparatedThreatScores`)
1. `overall_threat_score` (総合脅威スコア: 0-100)
2. `attack_severity_score` (攻撃深刻度: 0-100)
3. `defense_success_rate` (防御成功率: 0-100%)
4. `system_stability_score` (システム安定度: 0-100%)
5. `honeypot_lure_efficiency` (ハニーポット誘導効率: 0-100%)

### 3. 通信テレメトリ 7指標 (`SeparatedCommunicationTelemetry`)
1. `packets_per_sec_bigint` / `pps_formatted` (Packets/sec)
2. `bytes_per_sec_bigint` / `bps_formatted` (Bytes/sec, Gbps/Tbps/Pbps/Ebps自動単位変換)
3. `active_sessions_bigint` (Active Sessions)
4. `blocked_sessions_bigint` (Blocked Sessions)
5. `honeypot_rerouted_sessions_bigint` (Honeypot Rerouted Sessions)
6. `latency_ms` (Latency ms)
7. `packet_loss_pct` (Packet Loss %)
