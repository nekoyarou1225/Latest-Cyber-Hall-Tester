# ZUNDAMON_VOICEVOX_SPEC.md
## THUNDERHALL (サンダーホール) — ずんだもん6衣装 & ローカルVOICEVOX連携仕様書

### 1. ずんだもん全6衣装 (`ZUNDAMON_COSTUMES`)
1. `NORMAL_ZUNDAMON`: 通常オペレーター衣装
2. `CYBER_OPERATOR_ZUNDAMON`: サイバーオペレーター衣装（ネオンバイザー）
3. `TACTICAL_RESPONDER_ZUNDAMON`: 戦術防衛レスポンダー衣装
4. `RED_ALERT_COMMANDER_ZUNDAMON`: レッドアラート司令官衣装（緊急警報・重大脅威時）
5. `GOLD_JACKPOT_FESTIVAL_ZUNDAMON`: ゴールドジャックポット祝祭衣装
6. `SUPREME_GOLDEN_ZUNDAMON`: 至高の黄金ずんだもん（Core Breach / 1京スケール防衛達成時）

### 2. VOICEVOX ローカル限定接続 (`127.0.0.1:50021`)
- 接続先はハードコードされたループバックアドレス `http://127.0.0.1:50021` のみ (`local_only_verified: true`)。
- ローカル VOICEVOX エンジン未起動時は自動的にブラウザ Web Speech API (`ja-JP`) + 字幕バナーへ優雅にフォールバックし、エラー停止しない。
- 利用クレジット表記: `VOICEVOX:ずんだもん (東北ずん子・ずんだもんプロジェクト準拠)` をUIおよびドキュメントに明記。
