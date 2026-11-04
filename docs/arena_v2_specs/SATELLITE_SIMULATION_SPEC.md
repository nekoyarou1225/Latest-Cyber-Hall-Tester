# SATELLITE_SIMULATION_SPEC.md
## THUNDERHALL (サンダーホール) — 衛星軌道通信シミュレーション仕様書

### 1. 概要
宇宙・衛星通信ルートを `SIMULATED SATELLITE ROUTE` として明示し、実衛星制御系とは完全分離された軌道テレメトリをシミュレートする。

### 2. 対応軌道 (`SATELLITE_ORBIT_NODES`)
1. **LEO (低軌道)**: 高度 550km / 傾斜角 53° / RTT 28.4ms / 地上局: 東京大手町IX・千葉印西DC
2. **MEO (中軌道)**: 高度 8,062km / 傾斜角 45° / RTT 112.0ms / 地上局: 茨城つくば・大阪堂島IX
3. **GEO (静止軌道)**: 高度 35,786km / 傾斜角 0.1° / RTT 478.5ms / 地上局: 沖縄那覇・横浜陸揚局
