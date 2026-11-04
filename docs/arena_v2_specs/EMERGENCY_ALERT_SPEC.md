# EMERGENCY_ALERT_SPEC.md
## THUNDERHALL (サンダーホール) — 公共緊急警報 最優先割り込み (Priority #1) 仕様書

### 1. 最優先割り込み原則 (`priority_rank: 1`)
地震（緊急地震速報 EEW）・津波警報・特別警報・Jアラート等の公共緊急警報（または訓練モード `DRILL_TEST`）が発令された場合、画面上のすべてのガチャ演出・Core Breach演出・VOICEVOX通常読み上げを即座に中断・ミュートし、最上部緊急バナーを表示するとともにずんだもんを `RED_ALERT_COMMANDER_ZUNDAMON` へ切り替える。

### 2. 偽緊急警報演出の厳格禁止
- ゲーム演出やガチャ演出として偽の緊急地震速報・Jアラートチャイムや表示を行うことを固く禁じる。
- API (`POST /api/arena/emergency-alert`) に対して `attempt_fake_game_alert: true` が送信された場合、HTTP 403 Forbidden (`FAKE_EMERGENCY_ALERT_FORBIDDEN`) で即座に拒否し、監査ログに記録する。
- 緊急警報発動中に `POST /api/arena/gachapon/spin` が呼ばれた場合、HTTP 409 Conflict (`GACHAPON_SUSPENDED_BY_EMERGENCY_ALERT`) でブロックする。
