# SAFE_REPRODUCIBILITY_SPEC.md
## THUNDERHALL (サンダーホール) — 9ステップ安全再現・自動ロールバック検証仕様書

### 1. 安全原則
- 実システム破壊禁止・実データの改ざん禁止・外部ネットワーク送信禁止。
- インメモリの隔離サンドボックス（Isolated Memory Sandbox）内でのみ境界条件入力を実行し、検証完了後に自動ロールバックを実施する。

### 2. 9ステップ検証パイプライン (`runSafe9StepVerificationSandbox`)
1. `InitialStateSnapshot`: 初期状態の SHA-256 ダイジェスト記録
2. `MinimalTriggerInput`: 最小再現入力（境界値ペイロード）の構築
3. `ExpectedNormalBehavior`: 期待される正常応答・不変条件の定義
4. `ActualAnomalousBehavior`: サンドボックス内での実挙動計測
5. `LogAndTraceCapture`: 監査トレース・スタック情報の採取
6. `ImpactScopeAnalysis`: 影響範囲および信頼境界への波及評価
7. `FixProposalGeneration`: 具体的なコード修正パッチ案の生成
8. `PostFixReVerification`: 仮想パッチ適用後の不変条件回復確認
9. `AutomaticRollback`: サンドボックスの破棄と初期状態ダイジェスト一致確認 (`rollback_completed: true`)
