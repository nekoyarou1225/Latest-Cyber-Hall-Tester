# SECURITY_PRIVACY_SEPARATION_SPEC.md
## THUNDERHALL (サンダーホール) — コアセキュリティ・演出レイヤ完全分離 & プライバシー保護仕様書

### 1. 一方向データフローと障害隔離 (Fault Isolation)
- コアセキュリティ層（RBAC、Ed25519ライセンス検証、256件超連番ハッシュチェーン監査ログ、AES-256-GCM Vault、Quorum承認）は `server.ts` の最上位ミドルウェアとして独立稼働する。
- V2 アリーナ・ガチャ・ずんだもん演出レイヤ (`src/arena/*`) はコア層の状態を参照する一方向（Read/Append-Audit）のみで構成され、`try/catch` 障害隔離により万が一演出系で例外が発生しても `/api/state` やコア防衛機能は100%継続稼働する。

### 2. 配信時プライバシー保護
- 画面表示およびSSE配信ペイロードには `password_hash`, `ed25519_private_key`, 生トークン等の機密情報を一切含めない。
- BotシミュレーションのIPアドレスはすべて RFC 5737 / RFC 3849 のドキュメント専用範囲に限定し、実在の第三者IPアドレスを攻撃元として表示しない。
