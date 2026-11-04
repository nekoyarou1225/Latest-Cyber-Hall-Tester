# JAPANESE_COMMENTARY_SPEC.md
## THUNDERHALL (サンダーホール) — 日英同時解説・専門用語ガイド仕様書

### 1. 概要
`src/arena/zundamon_voicevox_alert.ts` にて、セキュリティイベント発生時に英語技術ログと同時に、初心者にも直感的に理解できる日本語解説およびずんだもん音声用テキストをリアルタイム生成する。

### 2. 専門用語7種カード (`GLOSSARY_CARDS`)
1. `SYN Flood` (SYNフラッド攻撃)
2. `DDoS` (分散型サービス拒否攻撃)
3. `SQL Injection` (SQLインジェクション)
4. `Zero-Day Candidate` (ゼロデイ候補)
5. `Honeypot` (ハニーポット / おとりサーバー)
6. `False Positive` (誤検知 / フォルス・ポジティブ)
7. `Rate Limit` (レート制限 / 通信回数制限)
