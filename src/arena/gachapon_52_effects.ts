// ============================================================================
// 3D PHYSICAL GACHAPON ENGINE & COMPLETE 52-EFFECTS CATALOG
// Sections 11, 12, 13, 14
// ============================================================================

export type CapsuleRank = 'GREEN' | 'ORANGE' | 'RED' | 'GOLD';
export type AuxiliaryCapsuleEffect = 'NONE' | 'BLUE_MINI_CAPSULE' | 'YELLOW_UPGRADE_FLASH';
export type ExpectationMode = 'NORMAL' | 'CHANCE' | 'HOT' | 'JACKPOT' | 'PREMIUM_FREEZE';
export type EffectCategory =
  | 'CATEGORY_A_PRE_SPIN_OMENS'
  | 'CATEGORY_B_CAPSULE_UPGRADE'
  | 'CATEGORY_C_SNIPER_TARGET'
  | 'CATEGORY_D_ENVIRONMENTAL_UI'
  | 'CATEGORY_E_JACKPOT_SPECIAL'
  | 'CATEGORY_F_FAKE_REVERSAL';

export interface GachaponEffectSpec {
  effect_id: string; // EFFECT-01 .. EFFECT-52
  effect_number: number; // 1 .. 52
  category: EffectCategory;
  name_en: string;
  name_ja: string;
  visual_behavior_ja: string;
  camera_action: string;
  min_capsule_rank: CapsuleRank;
  zundamon_voice_line_ja: string;
}

export interface GachaponSpinResult {
  spin_id: string;
  triggered_by_finding_id: string;
  security_result_determined_first: true;
  expectation_mode: ExpectationMode;
  expectation_rate_label: string;
  initial_capsule_rank: CapsuleRank;
  final_capsule_rank: CapsuleRank;
  auxiliary_capsule: AuxiliaryCapsuleEffect;
  upgraded: boolean;
  core_breach_triggered: boolean;
  core_breach_12_steps: string[];
  selected_effects: GachaponEffectSpec[];
  physics_telemetry: {
    dome_capsules_count: number;
    crank_torque_nm: number;
    gravity_m_s2: number;
    restitution_coeff: number;
    tray_bounces: number;
    shell_open_angle_deg: number;
  };
  zundamon_costume: string;
  zundamon_commentary_ja: string;
  timestamp: string;
}

export const EXPECTATION_MODES_TABLE: Array<{
  mode: ExpectationMode;
  visual_sign: string;
  probability_label: string;
  weight_per_1000: number;
}> = [
  { mode: 'NORMAL', visual_sign: 'Green / Blue Light', probability_label: '80%', weight_per_1000: 800 },
  { mode: 'CHANCE', visual_sign: 'Yellow / Orange Light', probability_label: '15%', weight_per_1000: 150 },
  { mode: 'HOT', visual_sign: 'Red Light + Alarm', probability_label: '4%', weight_per_1000: 40 },
  { mode: 'JACKPOT', visual_sign: 'Rainbow + Gold Capsule', probability_label: '0.9%', weight_per_1000: 9 },
  { mode: 'PREMIUM_FREEZE', visual_sign: 'Blackout + Core Breach + Zundamon Cut-In', probability_label: '0.1%', weight_per_1000: 1 },
];

export const CORE_BREACH_12_STEPS: string[] = [
  'Step 01: 3D地球儀の通常自転が減速・完全停止 (Globe rotation slows and locks)',
  'Step 02: 周囲のUI照明がディムダウン暗転 (Ambient UI lights dim to blackout)',
  'Step 03: 重低音アラームチャイム＆パルス鳴動 (Deep alarm chime & sub-bass pulse)',
  'Step 04: 地殻プレートに沿って赤色プラズマ亀裂が走る (Red plasma cracks across tectonic lines)',
  'Step 05: 地球外殻プレートがメカニカルにスライド開口 (Outer shell plates slide open)',
  'Step 06: 地球中心部に超高輝度「Earth Core」が露出 (Inner Earth Core is revealed)',
  'Step 07: コア内部に浮遊する Gold / Red カプセルへカメラが急接近 (Camera zooms into floating core capsule)',
  'Step 08: 高精度スナイパースコープ (Sniper Reticle) がカプセルを多重ロックオン (Sniper reticle locks onto capsule)',
  'Step 09: オービタル・スナイパーショット発射＆衝撃波リング展開 (Sniper shot fires with shockwave)',
  'Step 10: カプセルシェルが黄金の光の粒子となって弾け飛ぶ (Capsule bursts open in golden particles)',
  'Step 11: 検証済み脆弱性レポート／完全防衛ホログラムが空間投影 (Verified finding hologram materializes)',
  'Step 12: 至高の黄金ずんだもん (Supreme Golden Zundamon) が登場し日本語実況解説 (Zundamon announces the result)',
];

export const EFFECTS_52_CATALOG: GachaponEffectSpec[] = [
  // Category A — Pre-Spin Omens (10)
  {
    effect_id: 'EFFECT-01',
    effect_number: 1,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Silent Drum',
    name_ja: 'サイレント・ドラム（静寂前兆）',
    visual_behavior_ja: 'BGMと回転音が突然消え、無音のままドーム内のカプセルが輝き始める高期待度前兆',
    camera_action: 'Slow Dolly-In to Dome',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'しーっ…！音が消えたのだ、ただごとじゃない気配なのだ！',
  },
  {
    effect_id: 'EFFECT-02',
    effect_number: 2,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Reverse Spin',
    name_ja: 'リバース・スピン（逆回転始動）',
    visual_behavior_ja: 'ドーム内のカプセル群が一瞬反時計回りに逆回転してから高速正回転へ突入',
    camera_action: 'Orbital Tilt 15 deg',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'あれれ！？カプセルが逆に回ったのだ！チャンスなのだ！',
  },
  {
    effect_id: 'EFFECT-03',
    effect_number: 3,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Double Crank',
    name_ja: 'ダブル・クランク（二段回転）',
    visual_behavior_ja: 'メタリックハンドルが自動で2回連続高速スピンしトルクゲージが上昇',
    camera_action: 'Close-Up on Crank Handle',
    min_capsule_rank: 'GREEN',
    zundamon_voice_line_ja: 'ハンドルが2回連続で回ったのだ！解析加速中なのだ！',
  },
  {
    effect_id: 'EFFECT-04',
    effect_number: 4,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Heavy Crank',
    name_ja: 'ヘビー・クランク（重圧火花）',
    visual_behavior_ja: 'ハンドルが重く軋み、ギア部からシアン色のスパーク火花が飛び散る',
    camera_action: 'Micro-Vibration on Handle',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'ぐぬぬ…ハンドルがすごく重いのだ！大物が入ってるかもなのだ！',
  },
  {
    effect_id: 'EFFECT-05',
    effect_number: 5,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Capsule Tremor',
    name_ja: 'カプセル・トレマー（共振振動）',
    visual_behavior_ja: '透明ドーム内の全カプセルが小刻みに共鳴バイブレーションを起こす',
    camera_action: 'Dome Macro Focus',
    min_capsule_rank: 'GREEN',
    zundamon_voice_line_ja: 'カプセルたちがプルプル震えて共鳴しているのだ！',
  },
  {
    effect_id: 'EFFECT-06',
    effect_number: 6,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Red Sparks',
    name_ja: 'レッド・スパークス（赤雷前兆）',
    visual_behavior_ja: 'ドーム下部から赤いプラズマ稲妻が立ち昇り高脅威検出を予告',
    camera_action: 'Low-Angle Upward Pan',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: '赤い稲妻が出たのだ！重要度の高いセキュリティイベントなのだ！',
  },
  {
    effect_id: 'EFFECT-07',
    effect_number: 7,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Gold Glimmer',
    name_ja: 'ゴールド・グリマー（黄金閃光）',
    visual_behavior_ja: 'カプセル群の奥深くで金色の閃光が一瞬だけキラリと煌めく',
    camera_action: 'Rack Focus to Core',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: '今、奥の方で金色の光がキラッと見えたのだ！！',
  },
  {
    effect_id: 'EFFECT-08',
    effect_number: 8,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Radar Ping Burst',
    name_ja: 'レーダー・ピン・バースト（3連ソナー）',
    visual_behavior_ja: '3D地球儀のソナー波紋とガチャドームが3連打で同期発光',
    camera_action: 'Split Dual Focus Globe & Dome',
    min_capsule_rank: 'GREEN',
    zundamon_voice_line_ja: '地球儀のソナーとガチャがシンクロしてるのだ！',
  },
  {
    effect_id: 'EFFECT-09',
    effect_number: 9,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Satellite Lock-On',
    name_ja: 'サテライト・ロックオン（軌道照射）',
    visual_behavior_ja: '軌道上の仮想衛星からガチャポンドーム頂点へ誘導レーザーが照射される',
    camera_action: 'Top-Down Orbital Track',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: '宇宙の衛星軌道からガチャにレーザーが繋がったのだ！',
  },
  {
    effect_id: 'EFFECT-10',
    effect_number: 10,
    category: 'CATEGORY_A_PRE_SPIN_OMENS',
    name_en: 'Zundamon Whisper',
    name_ja: 'ずんだもん・ウィスパー（ささやき予告）',
    visual_behavior_ja: 'ずんだもんが画面端からひょっこり顔を出して秘密の予告を囁く',
    camera_action: 'Right Panel Zoom-In',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: '（ひそひそ…）なんだかすごい発見が来そうな予感がするのだ…！',
  },

  // Category B — Capsule Upgrade Effects (10)
  {
    effect_id: 'EFFECT-11',
    effect_number: 11,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Green to Orange Bounce',
    name_ja: 'バウンド昇格（緑→オレンジ）',
    visual_behavior_ja: '排出トレイでバウンドした瞬間に緑カプセルがオレンジカプセルへ昇格',
    camera_action: 'Tray Follow Shot',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'ポンッと跳ねてオレンジカプセルにランクアップしたのだ！',
  },
  {
    effect_id: 'EFFECT-12',
    effect_number: 12,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Orange to Red Lightning',
    name_ja: 'ライトニング昇格（オレンジ→赤）',
    visual_behavior_ja: 'オレンジカプセルに電撃が走り、高脅威レッドカプセルへ変異',
    camera_action: 'Impact Zoom',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: 'バリバリッ！オレンジから赤カプセルに昇格したのだ！警戒レベル上昇なのだ！',
  },
  {
    effect_id: 'EFFECT-13',
    effect_number: 13,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Red to Gold Ascension',
    name_ja: 'ゴールデン・アセンション（赤→金昇格）',
    visual_behavior_ja: '赤カプセルが黄金の粒子に包まれ、最高峰ゴールドカプセルへ覚醒',
    camera_action: '360 Orbit Around Capsule',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: 'うわあああ！赤カプセルが黄金のゴールドカプセルに進化したのだ！！',
  },
  {
    effect_id: 'EFFECT-14',
    effect_number: 14,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Crack & Transform',
    name_ja: 'クラック＆トランスフォーム（殻割れ昇格）',
    visual_behavior_ja: '外側のカプセル殻にヒビが入り、中から一段階上の輝くカプセルが出現',
    camera_action: 'Macro Shell Fracture',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'パリンッ！外側の殻が割れて、中から上位カプセルが出てきたのだ！',
  },
  {
    effect_id: 'EFFECT-15',
    effect_number: 15,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Zundamon Hammer Upgrade',
    name_ja: 'ずんだもんハンマー昇格',
    visual_behavior_ja: 'ずんだもんの光のハンマーがカプセルをポコンと叩いて色を書き換える',
    camera_action: 'Side Action Cut',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'えいっ！ずんだもんハンマーでカプセルを強化したのだ！',
  },
  {
    effect_id: 'EFFECT-16',
    effect_number: 16,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Shield Bounce Upgrade',
    name_ja: 'イージスシールド反射昇格',
    visual_behavior_ja: '六角形防衛シールドに跳ね返ったエネルギーでカプセルがランクアップ',
    camera_action: 'Ricochet Track',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: '防衛シールドのエネルギーを吸収してランクアップしたのだ！',
  },
  {
    effect_id: 'EFFECT-17',
    effect_number: 17,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Laser Rewrite',
    name_ja: 'レーザー・リライト（光学書き換え）',
    visual_behavior_ja: 'シアン＆ゴールドの光学レーザーがカプセル表面のカラーコードを書き換える',
    camera_action: 'Laser Sweep Close-Up',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: '光学スキャナーがカプセルの重要度を上位に書き換えたのだ！',
  },
  {
    effect_id: 'EFFECT-18',
    effect_number: 18,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Twin Capsule Merge',
    name_ja: 'ツイン・マージ（二個合体昇格）',
    visual_behavior_ja: '同時に飛び出した2個の小カプセルが空中で融合し、1個の大カプセルへ変化',
    camera_action: 'Mid-Air Convergence',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: '2つのカプセルが空中で合体してパワーアップしたのだ！',
  },
  {
    effect_id: 'EFFECT-19',
    effect_number: 19,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Glitch Upgrade',
    name_ja: 'サイバーグリッチ昇格',
    visual_behavior_ja: 'デジタルグリッチノイズが走り、カプセルが上位色へ瞬時にシフト',
    camera_action: 'Digital Snap Zoom',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'ピピッ！デジタルノイズの向こうから上位カプセルが現れたのだ！',
  },
  {
    effect_id: 'EFFECT-20',
    effect_number: 20,
    category: 'CATEGORY_B_CAPSULE_UPGRADE',
    name_en: 'Rainbow Aura',
    name_ja: 'レインボー・オーラ（七色確定光）',
    visual_behavior_ja: 'カプセルの周囲に七色のホログラムリングが多重展開しGoldランクを告知',
    camera_action: 'Slow Halo Orbit',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: '虹色のオーラが出たのだ！これは最上位クラスの証なのだ！！',
  },

  // Category C — Sniper & Target Effects (8)
  {
    effect_id: 'EFFECT-21',
    effect_number: 21,
    category: 'CATEGORY_C_SNIPER_TARGET',
    name_en: 'Sniper Scope Lock-On',
    name_ja: 'スナイパースコープ・ロックオン',
    visual_behavior_ja: '精密照準レティクルが展開し、ターゲットカプセルの距離と脅威度を計測して狙撃開封',
    camera_action: 'First-Person Scope Zoom',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'スコープ展開！目標カプセルを精密ロックオンなのだ！',
  },
  {
    effect_id: 'EFFECT-22',
    effect_number: 22,
    category: 'CATEGORY_C_SNIPER_TARGET',
    name_en: 'Dual Crosshair',
    name_ja: 'デュアル・クロスヘア（二重照準）',
    visual_behavior_ja: '地球儀上の発信元ノードとガチャカプセルを2つの照準が同時にロックオン',
    camera_action: 'Dual Target Sync',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: '発信元ルートとカプセルを二重ロックオンしたのだ！逃がさないのだ！',
  },
  {
    effect_id: 'EFFECT-23',
    effect_number: 23,
    category: 'CATEGORY_C_SNIPER_TARGET',
    name_en: 'Orbital Laser Shot',
    name_ja: 'オービタル・レーザーショット',
    visual_behavior_ja: '静止軌道衛星から高出力レーザーが垂直降下しカプセルを一撃で開封',
    camera_action: 'Vertical Beam Track',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: '軌道衛星からレーザー発射！カプセルを一撃オープンなのだ！',
  },
  {
    effect_id: 'EFFECT-24',
    effect_number: 24,
    category: 'CATEGORY_C_SNIPER_TARGET',
    name_en: 'Firewall Interceptor',
    name_ja: 'ファイアウォール迎撃ショット',
    visual_behavior_ja: '日本の防衛ゲートウェイから迎撃パルスが発射され攻撃アークを無害化カプセルへ変換',
    camera_action: 'Japan Gateway Tracking',
    min_capsule_rank: 'GREEN',
    zundamon_voice_line_ja: 'ファイアウォール迎撃成功！攻撃テストを安全にブロックしたのだ！',
  },
  {
    effect_id: 'EFFECT-25',
    effect_number: 25,
    category: 'CATEGORY_C_SNIPER_TARGET',
    name_en: 'Honeypot Trap Snipe',
    name_ja: 'ハニーポット・トラップスナイプ',
    visual_behavior_ja: 'パープルレーザーが対象Botを射抜き、Outer/Innerハニーポット隔離空間へ転送',
    camera_action: 'Purple Warp Follow',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'おとりのハニーポット部屋へピシャリと誘導完了なのだ！',
  },
  {
    effect_id: 'EFFECT-26',
    effect_number: 26,
    category: 'CATEGORY_C_SNIPER_TARGET',
    name_en: 'Precision CVE Hit',
    name_ja: 'プレシジョン・CVE・ヒット',
    visual_behavior_ja: 'スコープ内にCVE/CWE識別コードが表示され、該当コンポーネントをピンポイント照合',
    camera_action: 'HUD Telemetry Zoom',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: '既知の脆弱性パターン（CVE/CWE）をピンポイントで照合したのだ！',
  },
  {
    effect_id: 'EFFECT-27',
    effect_number: 27,
    category: 'CATEGORY_C_SNIPER_TARGET',
    name_en: 'Zero-Day Radar Lock',
    name_ja: 'ゼロデイ候補・ヘキサラダーロック',
    visual_behavior_ja: '未知脆弱性候補専用の六角形バイオレット＆ゴールド照準が多重回転ロック',
    camera_action: 'Hexagonal Reticle Spin Zoom',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: '未知のゼロデイ候補専用レーダーが反応したのだ！サンドボックスで安全検証するのだ！',
  },
  {
    effect_id: 'EFFECT-28',
    effect_number: 28,
    category: 'CATEGORY_C_SNIPER_TARGET',
    name_en: 'Multi-Target Barrage',
    name_ja: 'マルチターゲット・一斉迎撃',
    visual_behavior_ja: '多数の小型レティクルがBotクラスタを一斉ロックオンし高速無害化',
    camera_action: 'Wide Battlefield Sweep',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: '大量のテストBotをまとめて一斉ロックオン＆ガードしたのだ！',
  },

  // Category D — Environmental & UI Effects (10)
  {
    effect_id: 'EFFECT-29',
    effect_number: 29,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Screen Shake Light',
    name_ja: 'ライト・バイブレーション',
    visual_behavior_ja: '中脅威イベント着弾時にコンソールフレームが軽快に振動',
    camera_action: 'Subtle Frame Impulse',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: 'おっと！少し揺れたのだ、中規模の負荷テストが来ているのだ！',
  },
  {
    effect_id: 'EFFECT-30',
    effect_number: 30,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Screen Shake Heavy',
    name_ja: 'ヘビー・インパクトシェイク',
    visual_behavior_ja: '重大発見またはGold排出時に重厚なカメラインパクトとゴールドエッジ発光',
    camera_action: 'Heavy Impulse + Edge Glow',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: 'ドカーンと大きな手応えなのだ！注目の検証結果が出るのだ！',
  },
  {
    effect_id: 'EFFECT-31',
    effect_number: 31,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Red Emergency Strobe',
    name_ja: 'レッド・アラート・パルス（安全周期）',
    visual_behavior_ja: '光感受性に配慮した滑らかな赤色フェードパルスで高脅威検査を通知',
    camera_action: 'Smooth Perimeter Pulse',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: 'レッドアラート点灯なのだ！サンダーホールの防御壁がフル稼働中なのだ！',
  },
  {
    effect_id: 'EFFECT-32',
    effect_number: 32,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Neon Grid Surge',
    name_ja: 'ネオングリッド・サージ',
    visual_behavior_ja: '3D戦場の床面サイバーグリッドに高輝度シアン電流波が走る',
    camera_action: 'Floor Grid Wave',
    min_capsule_rank: 'GREEN',
    zundamon_voice_line_ja: 'サイバーグリッドにエネルギーが満ちているのだ！',
  },
  {
    effect_id: 'EFFECT-33',
    effect_number: 33,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Earth Halo Pulse',
    name_ja: 'アース・ヘイロー・パルス（大気圏リング）',
    visual_behavior_ja: '3D地球儀の大気圏外周リングが波紋状に3段拡大',
    camera_action: 'Planetary Ring Pull-Back',
    min_capsule_rank: 'GREEN',
    zundamon_voice_line_ja: '地球全体のモニタリングリングが綺麗に広がったのだ！',
  },
  {
    effect_id: 'EFFECT-34',
    effect_number: 34,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Submarine Cable Flash',
    name_ja: '海底ケーブル・オールフラッシュ',
    visual_behavior_ja: '太平洋・大西洋・インド洋の海底ケーブル網が一斉にシアン＆ゴールド発光',
    camera_action: 'Oceanic Route Highlight',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: '世界中の海底ケーブルルートがピカッと可視化されたのだ！',
  },
  {
    effect_id: 'EFFECT-35',
    effect_number: 35,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Japan Shield Dome',
    name_ja: '日本列島イージス・シールドドーム展開',
    visual_behavior_ja: '北海道から沖縄まで日本列島全域を覆う六角形エメラルド防護ドームが展開',
    camera_action: 'Japan Archipelago Focus',
    min_capsule_rank: 'GREEN',
    zundamon_voice_line_ja: '日本列島を守るサンダーホール・シールドドームが展開されたのだ！安心なのだ！',
  },
  {
    effect_id: 'EFFECT-36',
    effect_number: 36,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Matrix Packet Rain',
    name_ja: 'マトリックス・パケットレイン',
    visual_behavior_ja: '背景空間に検証用16進数カナリアパケットの光の粒が降り注ぐ',
    camera_action: 'Depth Particle Layer',
    min_capsule_rank: 'GREEN',
    zundamon_voice_line_ja: 'たくさんの検査パケットデータを高速解析しているのだ！',
  },
  {
    effect_id: 'EFFECT-37',
    effect_number: 37,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'HUD Overdrive',
    name_ja: 'HUDオーバードライブ（黄金フレーム）',
    visual_behavior_ja: '5ゾーンすべてのテレメトリ枠が一時的にゴールド＆シアン発光モードへ変形',
    camera_action: 'Full UI Sync Glow',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: '全モニターがオーバードライブモードに入ったのだ！',
  },
  {
    effect_id: 'EFFECT-38',
    effect_number: 38,
    category: 'CATEGORY_D_ENVIRONMENTAL_UI',
    name_en: 'Slow-Motion Impact',
    name_ja: 'スローモーション・インパクト開封',
    visual_behavior_ja: 'カプセルがトレイに着地しパカッと開く瞬間をドラマチックなスロー演出で再生',
    camera_action: '0.25x Time-Dilation Macro',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: 'カプセルが開く決定的瞬間をスローモーションで見るのだ…！',
  },

  // Category E — High-Expectation & Jackpot Effects (10)
  {
    effect_id: 'EFFECT-39',
    effect_number: 39,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'Blackout Freeze',
    name_ja: 'ブラックアウト・フリーズ（0.1%プレミアム暗転）',
    visual_behavior_ja: '画面が一瞬完全ブラックアウト停止し、鼓動音の後に黄金の閃光が炸裂',
    camera_action: 'Freeze Frame -> Flash Zoom',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: 'あっ…画面が止まったのだ！？…来るのだ！プレミアム・フリーズなのだーー！！',
  },
  {
    effect_id: 'EFFECT-40',
    effect_number: 40,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'Countdown 3-2-1-0',
    name_ja: 'ホログラム・カウントダウン 3-2-1-0',
    visual_behavior_ja: '3D空間中央に巨大ホログラム数字「3 → 2 → 1 → 0」が投影され開封へ突入',
    camera_action: 'Synced Beat Push-In',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: 'カウントダウン開始なのだ！スリー、ツー、ワン、ゼロなのだー！！',
  },
  {
    effect_id: 'EFFECT-41',
    effect_number: 41,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'Zundamon Cut-In Banner',
    name_ja: 'ずんだもん激アツ横断カットイン',
    visual_behavior_ja: '画面中央を横断するネオンカットインバナーに覚醒ずんだもんが登場',
    camera_action: 'Diagonal Dynamic Banner',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: 'ずんだもん激アツカットインなのだ！超重要レポートが出現するのだ！！',
  },
  {
    effect_id: 'EFFECT-42',
    effect_number: 42,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'Golden Gachapon Mode',
    name_ja: 'ゴールデン・ガチャポン筐体覚醒',
    visual_behavior_ja: 'ガチャポンマシン全体のメタリックフレームが純金ゴールド塗装に変化',
    camera_action: 'Full Machine Pedestal Up',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: 'ガチャポンマシン全体がピッカピカの純金モードに変身したのだ！！',
  },
  {
    effect_id: 'EFFECT-43',
    effect_number: 43,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'All-Gold Drum',
    name_ja: 'オール・ゴールド・ドラム（全金封入）',
    visual_behavior_ja: '透明ドーム内のすべての待機カプセルが一斉にゴールドカプセルへ変化',
    camera_action: 'Dome 360 Golden Spin',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: 'ドームの中が全部ゴールドカプセルになったのだ！どれが出ても大当たりなのだ！',
  },
  {
    effect_id: 'EFFECT-44',
    effect_number: 44,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'Core Breach Sequence',
    name_ja: '【特別演出】アース・コア・ブリーチ（12段階地球核狙撃）',
    visual_behavior_ja: '3D地球儀の外殻が開いて内部コアが露出し、スナイパーショットでコア内のGoldカプセルを撃ち抜く最高峰演出',
    camera_action: '12-Step Cinematic Core Dive',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: '地球のコアが開いたのだ！！スナイパーロックオン…コア・ブリーチ大成功なのだーー！！',
  },
  {
    effect_id: 'EFFECT-45',
    effect_number: 45,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'One Quadrillion Wave',
    name_ja: '1京（One Quadrillion）プラネタリー・ウェーブ',
    visual_behavior_ja: '10^16（1京）スケール到達時に惑星規模の黄金リング波が全軌道へ拡散',
    camera_action: 'Deep Space Orbital Zoom-Out',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: 'ついに1京（10の16乗）スケール到達なのだ！宇宙規模の防衛ウェーブなのだ！',
  },
  {
    effect_id: 'EFFECT-46',
    effect_number: 46,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'Zero-Day Discovery Fanfare',
    name_ja: 'ゼロデイ候補実証ファンファーレ',
    visual_behavior_ja: 'POTENTIAL_ZERO_DAY の9ステップ安全サンドボックス実証成功を祝うファンファーレ＆証跡ホログラム',
    camera_action: 'Hologram Trophy Reveal',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: '未知の脆弱性候補をサンドボックスで安全に実証完了したのだ！大発見なのだ！',
  },
  {
    effect_id: 'EFFECT-47',
    effect_number: 47,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'Perfect Defense Victory',
    name_ja: 'パーフェクト・ディフェンス（完全防衛勝利）',
    visual_behavior_ja: '全テスト攻撃波を100%無害化・ハニーポット隔離した際の祝賀エメラルド＆ゴールド演出',
    camera_action: 'Victory Orbit Around Japan',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: 'パーフェクト・ディフェンス達成なのだ！すべてのテスト攻撃から完璧に守り抜いたのだ！',
  },
  {
    effect_id: 'EFFECT-48',
    effect_number: 48,
    category: 'CATEGORY_E_JACKPOT_SPECIAL',
    name_en: 'Rainbow Cyber Aurora',
    name_ja: 'レインボー・サイバーオーロラ',
    visual_behavior_ja: '3D地球儀の北極・南極から日本列島上空にかけて七色のサイバーオーロラが輝く',
    camera_action: 'Polar Aurora Tilt',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: '空に七色のサイバーオーロラがかかったのだ！とっても綺麗で最高の結果なのだ！',
  },

  // Category F — Fake / Reversal Effects (4)
  {
    effect_id: 'EFFECT-49',
    effect_number: 49,
    category: 'CATEGORY_F_FAKE_REVERSAL',
    name_en: 'Fake Normal End -> Re-Spin',
    name_ja: 'フェイク終了→「まだまだなのだ！」再回転',
    visual_behavior_ja: 'Greenカプセルで一旦終了したかに見せかけ、ずんだもんの掛け声でドラムが再始動し上位へ昇格',
    camera_action: 'Fake Pull-Back -> Sudden Whip Zoom',
    min_capsule_rank: 'ORANGE',
    zundamon_voice_line_ja: '普通の緑カプセルでおしまい…と見せかけて、まだまだなのだー！もう一回回るのだ！',
  },
  {
    effect_id: 'EFFECT-50',
    effect_number: 50,
    category: 'CATEGORY_F_FAKE_REVERSAL',
    name_en: 'Capsule Drop Miss -> Zundamon Catch',
    name_ja: 'シュート落下ミス→ずんだもん大逆転キャッチ',
    visual_behavior_ja: 'トレイから転がり落ちそうになったカプセルをずんだもんがダイビングキャッチしてRed/Goldへ変換',
    camera_action: 'Drop Follow -> Catch Freeze',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: 'あぶないっ！落ちそうだったカプセルをナイスキャッチして大逆転昇格なのだ！',
  },
  {
    effect_id: 'EFFECT-51',
    effect_number: 51,
    category: 'CATEGORY_F_FAKE_REVERSAL',
    name_en: 'False Alarm Cool-Down -> Sudden Spike',
    name_ja: '静穏クールダウン→緊急レーダー急上昇逆転',
    visual_behavior_ja: '一旦ランプが消えて平時に戻った直後、深層スキャン反応で一気にRed/Gold演出へ突入',
    camera_action: 'Calm Wide -> Sudden Red/Gold Spike',
    min_capsule_rank: 'RED',
    zundamon_voice_line_ja: '静かになったと思ったら…深層スキャンで重大な反応が見つかったのだ！逆転突入なのだ！',
  },
  {
    effect_id: 'EFFECT-52',
    effect_number: 52,
    category: 'CATEGORY_F_FAKE_REVERSAL',
    name_en: 'Final Frame Reversal',
    name_ja: 'ファイナルフレーム・ガラスクラッシュ大逆転',
    visual_behavior_ja: '結果表示パネルが閉じる最終フレームで画面ガラスが割れ、最上位Gold結果へ逆転書き換え',
    camera_action: 'Glass Shatter -> Gold Reveal',
    min_capsule_rank: 'GOLD',
    zundamon_voice_line_ja: '最後の1フレームで大逆転なのだーー！！ゴールドカプセル確定なのだ！！',
  },
];

let gachaponHistory: GachaponSpinResult[] = [];
let totalSpinsCounter = 0;

export function getCostumeForCapsuleRank(rank: CapsuleRank, coreBreach: boolean): string {
  if (coreBreach) return 'SUPREME_GOLDEN_ZUNDAMON';
  switch (rank) {
    case 'GOLD':
      return 'GOLD_JACKPOT_FESTIVAL_ZUNDAMON';
    case 'RED':
      return 'RED_ALERT_COMMANDER_ZUNDAMON';
    case 'ORANGE':
      return 'TACTICAL_RESPONDER_ZUNDAMON';
    case 'GREEN':
    default:
      return 'NORMAL_ZUNDAMON';
  }
}

// Section 12.1 Strict Rule: Security findings are determined FIRST by the inspection engine;
// Gachapon presentation is selected to match the verified severity/classification without fabricating findings.
export function executeGachaponSpinForFinding(params: {
  finding_id: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  classification: string;
  requested_effect_id?: string;
  force_core_breach?: boolean;
}): GachaponSpinResult {
  totalSpinsCounter += 1;
  const spinId = `GACHA-SPIN-${String(totalSpinsCounter).padStart(5, '0')}`;

  // Determine objective final capsule rank from verified security severity/classification first
  let finalRank: CapsuleRank = 'GREEN';
  let expectationMode: ExpectationMode = 'NORMAL';
  let expectationRateLabel = '80%';

  if (
    params.force_core_breach ||
    params.classification === 'POTENTIAL_ZERO_DAY' ||
    params.classification === 'CONFIRMED_VULNERABILITY' ||
    params.requested_effect_id === 'EFFECT-44'
  ) {
    finalRank = 'GOLD';
    expectationMode = params.force_core_breach || params.requested_effect_id === 'EFFECT-44' ? 'PREMIUM_FREEZE' : 'JACKPOT';
    expectationRateLabel = expectationMode === 'PREMIUM_FREEZE' ? '0.1%' : '0.9%';
  } else if (params.severity === 'CRITICAL' || params.severity === 'HIGH') {
    finalRank = 'RED';
    expectationMode = 'HOT';
    expectationRateLabel = '4%';
  } else if (params.severity === 'MEDIUM') {
    finalRank = 'ORANGE';
    expectationMode = 'CHANCE';
    expectationRateLabel = '15%';
  } else {
    finalRank = 'GREEN';
    expectationMode = 'NORMAL';
    expectationRateLabel = '80%';
  }

  // If a specific effect was requested for testing/verification, ensure the rank supports it
  const explicitEffect = params.requested_effect_id
    ? EFFECTS_52_CATALOG.find((e) => e.effect_id === params.requested_effect_id)
    : undefined;

  if (explicitEffect) {
    const rankOrder: Record<CapsuleRank, number> = { GREEN: 1, ORANGE: 2, RED: 3, GOLD: 4 };
    if (rankOrder[explicitEffect.min_capsule_rank] > rankOrder[finalRank]) {
      finalRank = explicitEffect.min_capsule_rank;
    }
  }

  const upgraded = finalRank === 'GOLD' || finalRank === 'RED';
  const initialRank: CapsuleRank = upgraded ? (finalRank === 'GOLD' ? 'RED' : 'ORANGE') : finalRank;
  const coreBreachTriggered =
    Boolean(params.force_core_breach) ||
    params.requested_effect_id === 'EFFECT-44' ||
    expectationMode === 'PREMIUM_FREEZE';

  // Pick 3 coordinated effects from the 52 catalog (Pre-spin + Upgrade/Sniper + Env/Jackpot)
  const selectedEffects: GachaponEffectSpec[] = [];
  if (explicitEffect) {
    selectedEffects.push(explicitEffect);
  }
  const preSpin = EFFECTS_52_CATALOG[(totalSpinsCounter - 1) % 10]; // EFFECT-01..10
  const midEffect = EFFECTS_52_CATALOG[10 + ((totalSpinsCounter - 1) % 18)]; // EFFECT-11..28
  const climaxEffect = coreBreachTriggered
    ? EFFECTS_52_CATALOG[43] // EFFECT-44 Core Breach
    : finalRank === 'GOLD'
      ? EFFECTS_52_CATALOG[38 + ((totalSpinsCounter - 1) % 10)] // EFFECT-39..48
      : EFFECTS_52_CATALOG[28 + ((totalSpinsCounter - 1) % 10)]; // EFFECT-29..38

  for (const eff of [preSpin, midEffect, climaxEffect]) {
    if (!selectedEffects.some((s) => s.effect_id === eff.effect_id)) {
      selectedEffects.push(eff);
    }
  }

  const auxiliary: AuxiliaryCapsuleEffect =
    finalRank === 'GREEN'
      ? 'BLUE_MINI_CAPSULE'
      : upgraded
        ? 'YELLOW_UPGRADE_FLASH'
        : 'NONE';

  const costume = getCostumeForCapsuleRank(finalRank, coreBreachTriggered);
  const primaryLine = selectedEffects[0]?.zundamon_voice_line_ja || 'ガチャカプセル排出完了なのだ！';

  const result: GachaponSpinResult = {
    spin_id: spinId,
    triggered_by_finding_id: params.finding_id,
    security_result_determined_first: true,
    expectation_mode: expectationMode,
    expectation_rate_label: expectationRateLabel,
    initial_capsule_rank: initialRank,
    final_capsule_rank: finalRank,
    auxiliary_capsule: auxiliary,
    upgraded,
    core_breach_triggered: coreBreachTriggered,
    core_breach_12_steps: coreBreachTriggered ? CORE_BREACH_12_STEPS : [],
    selected_effects: selectedEffects,
    physics_telemetry: {
      dome_capsules_count: 32,
      crank_torque_nm: 2.4,
      gravity_m_s2: 9.81,
      restitution_coeff: 0.65,
      tray_bounces: 3,
      shell_open_angle_deg: 135,
    },
    zundamon_costume: costume,
    zundamon_commentary_ja: primaryLine,
    timestamp: new Date().toISOString(),
  };

  gachaponHistory.unshift(result);
  if (gachaponHistory.length > 50) {
    gachaponHistory = gachaponHistory.slice(0, 50);
  }
  return result;
}

export function getGachaponEngineSnapshot() {
  return {
    total_effects_catalog_count: EFFECTS_52_CATALOG.length,
    expectation_table: EXPECTATION_MODES_TABLE,
    formal_capsule_ranks: ['GREEN', 'ORANGE', 'RED', 'GOLD'],
    auxiliary_capsule_types: ['BLUE_MINI_CAPSULE', 'YELLOW_UPGRADE_FLASH'],
    core_breach_12_steps_spec: CORE_BREACH_12_STEPS,
    total_spins: totalSpinsCounter,
    latest_spin: gachaponHistory[0] || null,
    recent_spins: gachaponHistory.slice(0, 10),
    catalog: EFFECTS_52_CATALOG,
  };
}
