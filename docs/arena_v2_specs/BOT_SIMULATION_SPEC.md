# BOT_SIMULATION_SPEC.md
## THUNDERHALL (サンダーホール) — 仮想Botアリーナシミュレータ仕様書

### 1. 概要
`src/arena/bot_arena_simulator.ts` にて実装。すべて `THUNDERHALL BOT ARENA SIMULATOR` ラベル付きの安全な内部メモリシミュレーションとして動作し、外部ネットワークへの実パケット送出は一切行わない (`external_packets_sent: 0`)。

### 2. RFC準拠テスト専用アドレス & MAC一意性保証
- **IPv4**: RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) のみ使用
- **IPv6**: RFC 3849 (`2001:db8::/32`) のみ使用
- **MACアドレス**: ローカル管理ユニキャストビット (`02:AA:XX:XX:XX:XX`) を用いた決定論的生成により、10,000台同時生成時も重複ゼロ (`unique_mac_count === 10000`) を数学的・プログラム的に保証。
