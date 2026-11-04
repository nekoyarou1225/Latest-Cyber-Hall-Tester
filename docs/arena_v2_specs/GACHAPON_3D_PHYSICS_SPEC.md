# GACHAPON_3D_PHYSICS_SPEC.md
## THUNDERHALL (サンダーホール) — 3D物理ガチャポン & 判定先行ルール仕様書

### 1. 判定先行の鉄則 (`security_result_determined_first: true`)
演出（ガチャポン抽選）がセキュリティ判定を変えることは一切ない。まず `ai_vuln_engine` または `bot_arena_simulator` が実際のセキュリティイベント重要度を確定し、その重要度に対応したカプセル色・エフェクトが物理演算ドームから排出される。

### 2. 3D物理剛体モデル (`GachaponPhysicsFrame`)
- 球体カプセル数: 18個（ガラスドーム内半径 $R_d = 1.45\text{m}$、球体半径 $r_c = 0.22\text{m}$）
- 重力加速度 $g = -9.81\text{m/s}^2$、空気抵抗減衰 $\gamma = 0.985$、球体間反発係数 $e = 0.78$、壁面摩擦係数 $\mu = 0.14$
- クォータニオン回転 (`qx, qy, qz, qw`) と角速度ベクトル (`wx, wy, wz`) により 60fps 描画。

### 3. カプセル期待度テーブル (`CAPSULE_EXPECTATION_TABLE`)
- **青 (BLUE)**: 期待度 80.0% — NORMAL (Effects #01–#12)
- **緑 (GREEN)**: 期待度 15.0% — ADVANCED (Effects #13–#24)
- **紫 (PURPLE)**: 期待度 4.0% — HIGH_ALERT (Effects #25–#34)
- **赤 (RED)**: 期待度 0.9% — CRITICAL_RARE (Effects #35–#42)
- **金/虹 (GOLD_RAINBOW)**: 期待度 0.1% — JACKPOT_CORE_BREACH (Effects #43–#52)
