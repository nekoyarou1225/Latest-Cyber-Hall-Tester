/**
 * THUNDERHALL TESTER — CINEMATIC SCENE TRANSITION ENGINE & 25-SCREEN ARCHITECTURE
 * Design System: GLOBAL CYBER DEFENSE COMMAND CENTER
 *
 * Implements Section 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17:
 *  - SceneManager (MAIN_MONITOR -> EVENT_TRANSITION -> FULLSCREEN_EVENT -> EVENT_RESULT -> RETURN_TRANSITION -> MAIN_MONITOR)
 *  - TransitionManager
 *  - EventPriorityManager (P1 Emergency > P2 Critical Security > P3 System Fault > P4 Normal > P5 Entertainment)
 *  - EventQueue
 *  - AnimationController (12 Fullscreen Event Scenes + 52 Effects Integration)
 *  - AudioManager (Web Audio Cyber SE + VOICEVOX 127.0.0.1:50021 Queue)
 *  - CameraDirector (Earth Camera Snapshot Save & Exact Restore)
 *  - ZundamonStageController (8 Expressions x 6 Costumes + Lip-Sync SVG Renderer)
 *  - AccessibilityManager (Low-Stimulus, Flash Reduction, Motion Reduction, Volume, Subtitles, Low-Spec)
 */

// ============================================================================
// 1. 12 FULLSCREEN EVENT SCENES CATALOG (Section 7.2 & Section 8)
// ============================================================================
export const FULLSCREEN_EVENT_SCENES = {
  EVENT_NORMAL: {
    id: 'EVENT_NORMAL',
    title_en: 'STANDARD CYBER INSPECTION',
    title_ja: '通常解析イベント演出',
    themeColor: '#35D9FF',
    secondaryColor: '#168BFF',
    rank: 'GREEN',
    priority: 5,
    zundamonExpression: 'EXPLAIN',
    zundamonCostume: 'NORMAL_ZUNDAMON',
    desc_ja: '国際通信ストリームの標準パケット整合性検証を実行中なのだ。'
  },
  EVENT_CHANCE: {
    id: 'EVENT_CHANCE',
    title_en: 'HIGH-CORRELATION ROUTE CHANCE',
    title_ja: '高相関チャンス経路検知演出',
    themeColor: '#FFB844',
    secondaryColor: '#35D9FF',
    rank: 'ORANGE',
    priority: 5,
    zundamonExpression: 'SURPRISED',
    zundamonCostume: 'CYBER_OPERATOR_ZUNDAMON',
    desc_ja: '多段中継ルートに特徴的なシグネチャ相関を検知！深層解析へ移行するのだ！'
  },
  EVENT_HOT: {
    id: 'EVENT_HOT',
    title_en: 'CRITICAL VECTOR HOT ALERT',
    title_ja: '高期待度ホットベクトル演出',
    themeColor: '#FF475F',
    secondaryColor: '#FFB844',
    rank: 'RED',
    priority: 4,
    zundamonExpression: 'ALERT',
    zundamonCostume: 'Tactical_RESPONDER_ZUNDAMON',
    desc_ja: '重要防衛境界で高リスク攻撃ベクトルを捕捉！9段階サンドボックスで完全封じ込め中なのだ！'
  },
  EVENT_JACKPOT: {
    id: 'EVENT_JACKPOT',
    title_en: 'ROYAL GOLD DEFENSE JACKPOT',
    title_ja: '黄金防衛ジャックポット完全制圧演出',
    themeColor: '#F5B942',
    secondaryColor: '#FFE3A0',
    rank: 'GOLD',
    priority: 4,
    zundamonExpression: 'VICTORY',
    zundamonCostume: 'GOLD_JACKPOT_FESTIVAL_ZUNDAMON',
    desc_ja: '全8種AIエンジンと耐量子PQC検証が完全一致！最高ランクの防衛制圧ジャックポットなのだ！'
  },
  EVENT_PREMIUM_FREEZE: {
    id: 'EVENT_PREMIUM_FREEZE',
    title_en: 'CHRONO-STASIS PREMIUM FREEZE',
    title_ja: 'プレミアムフリーズ覚醒演出',
    themeColor: '#FFE3A0',
    secondaryColor: '#35D9FF',
    rank: 'GOLD',
    priority: 4,
    zundamonExpression: 'SURPRISED',
    zundamonCostume: 'SUPREME_GOLDEN_ZUNDAMON',
    desc_ja: '時空間パケットフリーズ発動！1京規模の通信空間を静止させてゼロデイ候補を完全解剖するのだ！'
  },
  EVENT_SNIPER: {
    id: 'EVENT_SNIPER',
    title_en: 'ORBITAL SNIPER PRECISION LOCK-ON',
    title_ja: '精密ターゲット・スナイパー狙撃演出',
    themeColor: '#27E59A',
    secondaryColor: '#35D9FF',
    rank: 'RED',
    priority: 4,
    zundamonExpression: 'SERIOUS',
    zundamonCostume: 'Tactical_RESPONDER_ZUNDAMON',
    desc_ja: '長距離スナイパースコープが不正中継ノードをミリ秒単位でロックオン！ピンポイント検疫完了なのだ！'
  },
  EVENT_SATELLITE: {
    id: 'EVENT_SATELLITE',
    title_en: 'LEO/MEO/GEO SATELLITE CONVERGENCE',
    title_ja: '3軌道衛星コンバージェンス照射演出',
    themeColor: '#35D9FF',
    secondaryColor: '#F5B942',
    rank: 'GOLD',
    priority: 4,
    zundamonExpression: 'VICTORY',
    zundamonCostume: 'CYBER_OPERATOR_ZUNDAMON',
    desc_ja: '低軌道・中軌道・静止軌道の防衛衛星群が同期フォーメーションを展開！地球規模の同期検証なのだ！'
  },
  EVENT_CORE_ALERT: {
    id: 'EVENT_CORE_ALERT',
    title_en: 'EARTH CORE DEFENSE SHIELD OVERDRIVE',
    title_ja: '地球コア・マルチレイヤー防衛警報演出',
    themeColor: '#FF475F',
    secondaryColor: '#F5B942',
    rank: 'GOLD',
    priority: 2,
    zundamonExpression: 'SERIOUS',
    zundamonCostume: 'SUPREME_GOLDEN_ZUNDAMON',
    desc_ja: 'CORE隔離12段階シーケンス発動！地球中枢コアを保護する多重エネルギー障壁が最大出力で展開中なのだ！'
  },
  EVENT_ROOT_REVERSAL: {
    id: 'EVENT_ROOT_REVERSAL',
    title_en: 'ROOT PRIVILEGE GOLDEN REVERSAL',
    title_ja: 'ROOT権限奪還・黄金逆転演出',
    themeColor: '#F5B942',
    secondaryColor: '#27E59A',
    rank: 'GOLD',
    priority: 3,
    zundamonExpression: 'VICTORY',
    zundamonCostume: 'SUPREME_GOLDEN_ZUNDAMON',
    desc_ja: '疑似侵害シナリオからの大逆転！カーネル保護ゲートがROOT権限を瞬時に奪還して完全浄化したのだ！'
  },
  EVENT_DATA_REVERSAL: {
    id: 'EVENT_DATA_REVERSAL',
    title_en: 'QUANTUM DATA RECONSTRUCTION REVERSAL',
    title_ja: 'データ破損再構築・逆転突破演出',
    themeColor: '#35D9FF',
    secondaryColor: '#27E59A',
    rank: 'RED',
    priority: 4,
    zundamonExpression: 'HAPPY',
    zundamonCostume: 'GOLD_JACKPOT_FESTIVAL_ZUNDAMON',
    desc_ja: 'Ed25519署名バックアップから一瞬で無傷のデータを再構築！改ざん試行を無効化して逆転勝利なのだ！'
  },
  EVENT_STREAM_REVERSAL: {
    id: 'EVENT_STREAM_REVERSAL',
    title_en: 'HYPER-STREAM OVERRIDE REVERSAL',
    title_ja: '通信ストリーム高速オーバーライド逆転演出',
    themeColor: '#27E59A',
    secondaryColor: '#35D9FF',
    rank: 'ORANGE',
    priority: 4,
    zundamonExpression: 'HAPPY',
    zundamonCostume: 'CYBER_OPERATOR_ZUNDAMON',
    desc_ja: '飽和トラフィックをXDP高速フィルタで一掃！正規通信ストリームが100%クリーンに回復したのだ！'
  },
  EVENT_BLUE_SCREEN_REVERSAL: {
    id: 'EVENT_BLUE_SCREEN_REVERSAL',
    title_en: 'SYSTEM KERNEL AWAKENING REVERSAL',
    title_ja: 'ブルースクリーン・ゴールデン覚醒逆転演出',
    themeColor: '#F5B942',
    secondaryColor: '#168BFF',
    rank: 'GOLD',
    priority: 3,
    zundamonExpression: 'VICTORY',
    zundamonCostume: 'SUPREME_GOLDEN_ZUNDAMON',
    desc_ja: 'フェイク停止演出からのTHUNDERHALL黄金リカバリ発動！SafetyGuardの自己修復で無敵復帰したのだ！'
  }
};

/**
 * Maps any of the 52 Effect IDs (EFFECT-01 .. EFFECT-52) to one of the 12 Fullscreen Event Scenes
 */
export function mapEffectIdToSceneKey(effectId, capsuleRank = 'GREEN', coreBreach = false) {
  if (coreBreach || effectId === 'EFFECT-44') return 'EVENT_CORE_ALERT';
  const num = parseInt(String(effectId || '').replace('EFFECT-', ''), 10) || 1;
  if (num === 45 || num === 46) return 'EVENT_PREMIUM_FREEZE';
  if (num === 47) return 'EVENT_ROOT_REVERSAL';
  if (num === 48) return 'EVENT_DATA_REVERSAL';
  if (num === 49) return 'EVENT_STREAM_REVERSAL';
  if (num === 50) return 'EVENT_BLUE_SCREEN_REVERSAL';
  if (num === 51 || num === 52) return 'EVENT_JACKPOT';
  if (num >= 36 && num <= 40) return 'EVENT_SNIPER';
  if (num >= 41 && num <= 43) return 'EVENT_SATELLITE';
  if (capsuleRank === 'GOLD') return 'EVENT_JACKPOT';
  if (capsuleRank === 'RED') return 'EVENT_HOT';
  if (capsuleRank === 'ORANGE') return 'EVENT_CHANCE';
  return 'EVENT_NORMAL';
}

// ============================================================================
// 2. ALL 25 UNIFIED SYSTEM SCREENS DIRECTORY (Section 12)
// ============================================================================
export const ALL_25_SCREENS = [
  { num: 1, id: 'SCREEN_01_MAIN_MONITOR', title_ja: '01. メイン監視画面 (3D地球コマンド)', title_en: 'MAIN MONITOR', type: 'main', tab: 'OVERVIEW' },
  { num: 2, id: 'SCREEN_02_SYSTEM_OVERVIEW', title_ja: '02. システム概要画面', title_en: 'SYSTEM OVERVIEW', type: 'module', modId: 'overview', tab: 'OVERVIEW' },
  { num: 3, id: 'SCREEN_03_NETWORK_ANALYSIS', title_ja: '03. ネットワーク解析・国際通信画面', title_en: 'NETWORK ANALYSIS', type: 'sidebar', tab: 'NETWORK' },
  { num: 4, id: 'SCREEN_04_BOT_ARENA', title_ja: '04. ボットアリーナ (1〜1京台) 画面', title_en: 'BOT ARENA', type: 'module', modId: 'bot-lab', tab: 'ANALYSIS' },
  { num: 5, id: 'SCREEN_05_SECURITY_TESTING', title_ja: '05. セキュリティ検査実行画面', title_en: 'SECURITY TESTING', type: 'sidebar', tab: 'SECURITY' },
  { num: 6, id: 'SCREEN_06_VULNERABILITY_LIST', title_ja: '06. 脆弱性一覧 (CVE/CWE) 画面', title_en: 'VULNERABILITY LIST', type: 'sidebar', tab: 'SECURITY' },
  { num: 7, id: 'SCREEN_07_ZERODAY_CANDIDATES', title_ja: '07. ゼロデイ候補・9段サンドボックス画面', title_en: 'ZERO-DAY CANDIDATES', type: 'sidebar', tab: 'SECURITY' },
  { num: 8, id: 'SCREEN_08_SCAN_PROGRESS', title_ja: '08. スキャン進行・パイプライン制御画面', title_en: 'SCAN PROGRESS', type: 'module', modId: 'packet-sim', tab: 'SECURITY' },
  { num: 9, id: 'SCREEN_09_SCAN_RESULTS', title_ja: '09. スキャン結果・DPI/XDP検証画面', title_en: 'SCAN RESULTS', type: 'module', modId: 'dpi-xdp', tab: 'ANALYSIS' },
  { num: 10, id: 'SCREEN_10_DETAILED_REPORT', title_ja: '10. 詳細監査レポート・SHA256検査画面', title_en: 'DETAILED REPORT', type: 'module', modId: 'file-inspector', tab: 'ANALYSIS' },
  { num: 11, id: 'SCREEN_11_LOGS', title_ja: '11. 改ざん防止SHA-256監査ログ画面', title_en: 'AUDIT LOGS', type: 'module', modId: 'audit-settings', tab: 'OVERVIEW' },
  { num: 12, id: 'SCREEN_12_EVENT_HISTORY', title_ja: '12. イベント履歴・タイムライン画面', title_en: 'EVENT HISTORY', type: 'sidebar', tab: 'EVENTS' },
  { num: 13, id: 'SCREEN_13_ZUNDAMON_SETTINGS', title_ja: '13. ずんだもん衣装(6種)・表情(8種)設定画面', title_en: 'ZUNDAMON STAGE', type: 'sidebar', tab: 'SYSTEM' },
  { num: 14, id: 'SCREEN_14_AUDIO_SETTINGS', title_ja: '14. 音声・VOICEVOX・SEミキサー設定画面', title_en: 'AUDIO & VOICEVOX', type: 'module', modId: 'audio-mixer', tab: 'SYSTEM' },
  { num: 15, id: 'SCREEN_15_OBS_SETTINGS', title_ja: '15. OBS配信連携・16:9スタジオ設定画面', title_en: 'OBS BROADCAST', type: 'module', modId: 'tester-studio', tab: 'SYSTEM' },
  { num: 16, id: 'SCREEN_16_EMERGENCY_INFO', title_ja: '16. 緊急情報 (J-Alert/地震/津波) 最優先画面', title_en: 'EMERGENCY ALERT', type: 'emergency', tab: 'SYSTEM' },
  { num: 17, id: 'SCREEN_17_GACHAPON_SCENE', title_ja: '17. 3Dガラポン専用全画面イベントシーン', title_en: '3D GACHAPON SCENE', type: 'gachapon', tab: 'EVENTS' },
  { num: 18, id: 'SCREEN_18_EFFECT_SETTINGS', title_ja: '18. 全52種演出カタログ・12全画面演出設定', title_en: '52 EFFECTS CATALOG', type: 'sidebar', tab: 'EVENTS' },
  { num: 19, id: 'SCREEN_19_ACCOUNT_SETTINGS', title_ja: '19. オペレーターRBACアカウント・CSRF管理画面', title_en: 'ACCOUNT & RBAC', type: 'sidebar', tab: 'SYSTEM' },
  { num: 20, id: 'SCREEN_20_LICENSE_SETTINGS', title_ja: '20. 32段階Ed25519ライセンス・契約区分画面', title_en: '32-TIER LICENSE', type: 'modal', modalId: 'modal-plan-matrix', tab: 'SYSTEM' },
  { num: 21, id: 'SCREEN_21_ADMIN_CONSOLE', title_ja: '21. 管理者Quorum承認・Kill Switch統制画面', title_en: 'ADMIN QUORUM', type: 'module', modId: 'sec-events', tab: 'SECURITY' },
  { num: 22, id: 'SCREEN_22_HELP_DOCS', title_ja: '22. ヘルプ・初心者向けセキュリティ用語集画面', title_en: 'HELP & GLOSSARY', type: 'custom_drawer', viewKey: 'help', tab: 'OVERVIEW' },
  { num: 23, id: 'SCREEN_23_ERROR_FALLBACK', title_ja: '23. エラー診断・SafetyGuardフォールバック画面', title_en: 'SAFETY DIAGNOSTICS', type: 'module', modId: 'device-mon', tab: 'SYSTEM' },
  { num: 24, id: 'SCREEN_24_INITIAL_BOOT', title_ja: '24. 初期起動シネマティック・ブートシーケンス画面', title_en: 'BOOT SEQUENCE', type: 'custom_drawer', viewKey: 'boot', tab: 'SYSTEM' },
  { num: 25, id: 'SCREEN_25_LOADING_TRANSITION', title_ja: '25. シーン遷移・トランジションゲート画面', title_en: 'SCENE TRANSITION', type: 'transition_preview', tab: 'EVENTS' }
];

// ============================================================================
// 3. ACCESSIBILITY & SENSORY LOAD MANAGER (Section 17)
// ============================================================================
export class AccessibilityManager {
  constructor() {
    this.settings = {
      lowStimulusMode: false,
      reduceFlash: false,
      reduceMotion: false,
      seVolume: 0.65,
      voiceVolume: 0.85,
      subtitleEnabled: true,
      subtitleScale: 'M', // 'S' | 'M' | 'L'
      lowSpecMode: false
    };
    this.loadFromStorage();
  }

  loadFromStorage() {
    try {
      const raw = localStorage.getItem('thunderhall_a11y_v3');
      if (raw) {
        const parsed = JSON.parse(raw);
        this.settings = { ...this.settings, ...parsed };
      }
    } catch {
      // ignore storage errors
    }
  }

  saveToStorage() {
    try {
      localStorage.setItem('thunderhall_a11y_v3', JSON.stringify(this.settings));
    } catch {
      // ignore
    }
  }

  updateSetting(key, value) {
    if (!(key in this.settings)) return;
    this.settings[key] = value;
    this.saveToStorage();
    this.applyToDocument();
  }

  applyToDocument() {
    const body = document.body;
    if (!body) return;
    body.classList.toggle('a11y-low-stimulus', Boolean(this.settings.lowStimulusMode));
    body.classList.toggle('a11y-reduce-flash', Boolean(this.settings.reduceFlash));
    body.classList.toggle('a11y-reduce-motion', Boolean(this.settings.reduceMotion));

    const subEl = document.getElementById('zundamon-live-subtitle-box');
    if (subEl) {
      subEl.style.display = this.settings.subtitleEnabled ? 'block' : 'none';
      subEl.style.fontSize =
        this.settings.subtitleScale === 'L' ? '13px' : this.settings.subtitleScale === 'S' ? '10px' : '11px';
    }

    if (window.ThunderhallEarth3D && typeof window.ThunderhallEarth3D.setPerformanceOptions === 'function') {
      window.ThunderhallEarth3D.setPerformanceOptions({
        reduceMotion: Boolean(this.settings.reduceMotion),
        lowSpecMode: Boolean(this.settings.lowSpecMode)
      });
    }
  }
}

// ============================================================================
// 4. AUDIO & VOICEVOX QUEUE MANAGER (Section 10 & 15)
// ============================================================================
export class AudioManager {
  constructor(a11y) {
    this.a11y = a11y;
    this.ctx = null;
    this.emergencyMuted = false;
  }

  ensureContext() {
    if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      this.ctx = new Ctx();
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
  }

  playCyberSe(type = 'transition') {
    if (this.emergencyMuted || this.a11y.settings.lowStimulusMode) return;
    const vol = Number(this.a11y.settings.seVolume ?? 0.65);
    if (vol <= 0.01) return;

    try {
      this.ensureContext();
      if (!this.ctx) return;
      const now = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.connect(gain);
      gain.connect(this.ctx.destination);

      if (type === 'jackpot') {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(523.25, now);
        osc.frequency.exponentialRampToValueAtTime(1046.5, now + 0.35);
        gain.gain.setValueAtTime(vol * 0.18, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.42);
        osc.start(now);
        osc.stop(now + 0.42);
      } else if (type === 'alert') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(440, now);
        osc.frequency.setValueAtTime(660, now + 0.12);
        gain.gain.setValueAtTime(vol * 0.14, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
        osc.start(now);
        osc.stop(now + 0.3);
      } else {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(320, now);
        osc.frequency.exponentialRampToValueAtTime(640, now + 0.18);
        gain.gain.setValueAtTime(vol * 0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
        osc.start(now);
        osc.stop(now + 0.22);
      }
    } catch {
      // ignore audio autoplay restriction
    }
  }

  stopAllImmediately() {
    this.emergencyMuted = true;
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
  }

  clearEmergencyMute() {
    this.emergencyMuted = false;
  }
}

// ============================================================================
// 5. CAMERA DIRECTOR (Section 15)
// ============================================================================
export class CameraDirector {
  constructor() {
    this.savedEarthSnapshot = null;
  }

  captureMainMonitorState() {
    if (window.ThunderhallEarth3D && typeof window.ThunderhallEarth3D.saveViewState === 'function') {
      this.savedEarthSnapshot = window.ThunderhallEarth3D.saveViewState();
    }
  }

  playTransitionZoomIn() {
    if (window.ThunderhallEarth3D && typeof window.ThunderhallEarth3D.focusLatLon === 'function') {
      const snap = this.savedEarthSnapshot || { currentLat: 35.68, currentLon: 139.69 };
      window.ThunderhallEarth3D.focusLatLon(snap.currentLat, snap.currentLon, 16.2);
    }
  }

  restoreMainMonitorState() {
    if (
      this.savedEarthSnapshot &&
      window.ThunderhallEarth3D &&
      typeof window.ThunderhallEarth3D.restoreViewState === 'function'
    ) {
      window.ThunderhallEarth3D.restoreViewState(this.savedEarthSnapshot);
    }
  }
}

// ============================================================================
// 6. EVENT PRIORITY MANAGER & EVENT QUEUE (Section 11, 14, 15)
// ============================================================================
export class EventPriorityManager {
  constructor() {
    // Priority 1 (Highest) -> Priority 5 (Lowest)
    this.PRIORITY = {
      P1_EMERGENCY: 1,
      P2_CRITICAL_SECURITY: 2,
      P3_SYSTEM_FAULT: 3,
      P4_NORMAL_EVENT: 4,
      P5_ENTERTAINMENT: 5
    };
    this.currentActivePriority = null;
  }

  canPreempt(incomingPriority) {
    if (this.currentActivePriority === null) return true;
    return incomingPriority <= this.currentActivePriority;
  }
}

export class EventQueue {
  constructor() {
    this.queue = [];
  }

  enqueue(eventItem) {
    this.queue.push(eventItem);
    this.queue.sort((a, b) => (a.priority || 5) - (b.priority || 5));
  }

  dequeue() {
    return this.queue.shift() || null;
  }

  clearLowerPriorityThan(priorityLevel) {
    this.queue = this.queue.filter((item) => (item.priority || 5) < priorityLevel);
  }

  clearAll() {
    this.queue = [];
  }
}

// ============================================================================
// 7. ZUNDAMON 8-EXPRESSION x 6-COSTUME STAGE CONTROLLER (Section 10)
// ============================================================================
export class ZundamonStageController {
  constructor() {
    this.currentExpression = 'NORMAL';
    this.currentCostume = 'NORMAL_ZUNDAMON';
    this.mouthOpen = false;
    this.lipSyncTimer = null;

    this.EXPRESSIONS = {
      NORMAL: { label_ja: '通常', eyes: 'normal', mouth: 'smile', badgeColor: '#27E59A' },
      HAPPY: { label_ja: '喜び', eyes: 'happy', mouth: 'open_smile', badgeColor: '#27E59A' },
      SURPRISED: { label_ja: '驚き', eyes: 'wide', mouth: 'o_mouth', badgeColor: '#35D9FF' },
      ALERT: { label_ja: '警戒', eyes: 'sharp', mouth: 'firm', badgeColor: '#FFB844' },
      SERIOUS: { label_ja: '真剣', eyes: 'focused', mouth: 'line', badgeColor: '#168BFF' },
      EXPLAIN: { label_ja: '解説', eyes: 'wink', mouth: 'talk', badgeColor: '#35D9FF' },
      VICTORY: { label_ja: '勝利', eyes: 'star', mouth: 'big_smile', badgeColor: '#F5B942' },
      EMERGENCY: { label_ja: '緊急', eyes: 'urgent', mouth: 'strict', badgeColor: '#FF475F' }
    };

    this.COSTUMES = {
      NORMAL_ZUNDAMON: { name_ja: '通常衣装', accent: '#27E59A', visor: false, crown: false },
      CYBER_OPERATOR_ZUNDAMON: { name_ja: 'オペレーター衣装', accent: '#35D9FF', visor: true, crown: false },
      Tactical_RESPONDER_ZUNDAMON: { name_ja: 'サイバー防衛服', accent: '#168BFF', visor: true, crown: false },
      RED_ALERT_COMMANDER_ZUNDAMON: { name_ja: '緊急防護服', accent: '#FF475F', visor: true, crown: false },
      GOLD_JACKPOT_FESTIVAL_ZUNDAMON: { name_ja: '金色特別衣装', accent: '#F5B942', visor: false, crown: true },
      SUPREME_GOLDEN_ZUNDAMON: { name_ja: '解析・黄金覚醒モード', accent: '#FFE3A0', visor: true, crown: true }
    };
  }

  setState({ expression, costume, speakingDurationMs = 0 } = {}) {
    if (expression && this.EXPRESSIONS[expression]) {
      this.currentExpression = expression;
    }
    if (costume && this.COSTUMES[costume]) {
      this.currentCostume = costume;
    }
    if (speakingDurationMs > 0) {
      this.startLipSync(speakingDurationMs);
    }
    this.renderAvatar();
  }

  startLipSync(durationMs = 2400) {
    if (this.lipSyncTimer) clearInterval(this.lipSyncTimer);
    const endAt = performance.now() + durationMs;
    this.lipSyncTimer = setInterval(() => {
      if (performance.now() >= endAt || window.emergencyOverrideActive) {
        clearInterval(this.lipSyncTimer);
        this.lipSyncTimer = null;
        this.mouthOpen = false;
        this.renderAvatar();
        return;
      }
      this.mouthOpen = !this.mouthOpen;
      this.renderAvatar();
    }, 140);
  }

  buildSvgMarkup() {
    const exp = this.EXPRESSIONS[this.currentExpression] || this.EXPRESSIONS.NORMAL;
    const cos = this.COSTUMES[this.currentCostume] || this.COSTUMES.NORMAL_ZUNDAMON;
    const accent = cos.accent;

    const mouthPath = this.mouthOpen
      ? `<ellipse cx="48" cy="60" rx="6" ry="5" fill="#FF475F" stroke="#030914" stroke-width="1.5"/>`
      : exp.mouth === 'strict' || exp.mouth === 'line'
        ? `<line x1="42" y1="60" x2="54" y2="60" stroke="#030914" stroke-width="2.2" stroke-linecap="round"/>`
        : `<path d="M 41 58 Q 48 64 55 58" fill="none" stroke="#030914" stroke-width="2.2" stroke-linecap="round"/>`;

    const eyesMarkup =
      exp.eyes === 'happy'
        ? `<path d="M 33 46 Q 37 41 41 46" fill="none" stroke="#030914" stroke-width="2.4" stroke-linecap="round"/>
           <path d="M 55 46 Q 59 41 63 46" fill="none" stroke="#030914" stroke-width="2.4" stroke-linecap="round"/>`
        : `<ellipse cx="37" cy="46" rx="4.2" ry="5.2" fill="#030914"/>
           <ellipse cx="59" cy="46" rx="4.2" ry="5.2" fill="#030914"/>
           <circle cx="38.5" cy="44" r="1.6" fill="#FFFFFF"/>
           <circle cx="60.5" cy="44" r="1.6" fill="#FFFFFF"/>`;

    const visorMarkup = cos.visor
      ? `<rect x="28" y="40" width="40" height="10" rx="4" fill="${accent}" fill-opacity="0.32" stroke="${accent}" stroke-width="1.4"/>`
      : '';

    const crownMarkup = cos.crown
      ? `<polygon points="36,20 42,10 48,18 54,10 60,20" fill="#F5B942" stroke="#FFE3A0" stroke-width="1.2"/>`
      : '';

    return `
      <svg viewBox="0 0 96 96" class="w-full h-full">
        <defs>
          <radialGradient id="zundaBg" cx="50%" cy="45%" r="55%">
            <stop offset="0%" stop-color="${accent}" stop-opacity="0.35"/>
            <stop offset="100%" stop-color="#030914" stop-opacity="0.95"/>
          </radialGradient>
        </defs>
        <rect x="2" y="2" width="92" height="92" rx="14" fill="url(#zundaBg)" stroke="${accent}" stroke-width="2"/>
        <!-- Edamame Ears -->
        <ellipse cx="22" cy="24" rx="9" ry="15" transform="rotate(-24 22 24)" fill="#27E59A" stroke="#030914" stroke-width="1.8"/>
        <ellipse cx="74" cy="24" rx="9" ry="15" transform="rotate(24 74 24)" fill="#27E59A" stroke="#030914" stroke-width="1.8"/>
        ${crownMarkup}
        <!-- Hair & Head -->
        <circle cx="48" cy="48" r="24" fill="#FFE8D6" stroke="#030914" stroke-width="1.8"/>
        <path d="M 24 44 Q 30 22 48 22 Q 66 22 72 44 Q 60 34 48 36 Q 36 34 24 44 Z" fill="#27E59A" stroke="#030914" stroke-width="1.5"/>
        ${eyesMarkup}
        ${visorMarkup}
        ${mouthPath}
        <!-- Cyber Collar / Costume -->
        <path d="M 26 72 L 38 68 L 48 76 L 58 68 L 70 72 L 76 90 L 20 90 Z" fill="#091C30" stroke="${accent}" stroke-width="2"/>
      </svg>
    `;
  }

  renderAvatar() {
    const box = document.getElementById('zundamon-avatar-box');
    if (box) {
      box.innerHTML = this.buildSvgMarkup();
    }
    const expBadge = document.getElementById('zundamon-expression-badge');
    if (expBadge) {
      const exp = this.EXPRESSIONS[this.currentExpression] || this.EXPRESSIONS.NORMAL;
      expBadge.textContent = `表情: ${exp.label_ja} (${this.currentExpression})`;
      expBadge.style.borderColor = exp.badgeColor;
      expBadge.style.color = exp.badgeColor;
    }
  }
}

// ============================================================================
// 8. ANIMATION CONTROLLER FOR 12 FULLSCREEN SCENES (Section 7, 8, 15)
// ============================================================================
export class AnimationController {
  constructor(a11y) {
    this.a11y = a11y;
    this.activeSceneKey = 'EVENT_NORMAL';
    this.animFrameId = null;
    this.particles = [];
    this.startTime = 0;
  }

  startFullscreenCanvasEffect(canvasEl, sceneSpec) {
    if (!canvasEl) return;
    this.stopFullscreenCanvasEffect();
    this.activeSceneKey = sceneSpec.id;
    this.startTime = performance.now();

    const count = this.a11y.settings.lowSpecMode ? 24 : 56;
    this.particles = Array.from({ length: count }, (_, idx) => ({
      x: Math.random(),
      y: Math.random(),
      vx: (Math.random() - 0.5) * 0.006,
      vy: (Math.random() - 0.5) * 0.006,
      radius: 1.5 + (idx % 4) * 1.2,
      phase: idx * 0.4
    }));

    const render = (now) => {
      this.animFrameId = requestAnimationFrame(render);
      const w = canvasEl.clientWidth || 960;
      const h = canvasEl.clientHeight || 540;
      if (canvasEl.width !== w || canvasEl.height !== h) {
        canvasEl.width = w;
        canvasEl.height = h;
      }
      const ctx = canvasEl.getContext('2d');
      if (!ctx) return;

      const elapsed = (now - this.startTime) / 1000;
      ctx.clearRect(0, 0, w, h);

      // Deep space radial backdrop
      const grad = ctx.createRadialGradient(w * 0.5, h * 0.5, 10, w * 0.5, h * 0.5, Math.max(w, h) * 0.65);
      grad.addColorStop(0, 'rgba(16, 42, 66, 0.85)');
      grad.addColorStop(0.55, 'rgba(7, 20, 38, 0.94)');
      grad.addColorStop(1, 'rgba(3, 9, 20, 0.98)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, w, h);

      // Scene-specific geometric HUD rings (Sniper reticle, Satellite orbits, Core shield, or Jackpot rays)
      const cx = w * 0.5;
      const cy = h * 0.5;
      const baseR = Math.min(w, h) * 0.28;

      ctx.save();
      ctx.translate(cx, cy);
      ctx.strokeStyle = sceneSpec.themeColor || '#35D9FF';
      ctx.lineWidth = 2;

      for (let r = 1; r <= 3; r++) {
        ctx.beginPath();
        ctx.arc(0, 0, baseR * (0.45 * r), 0, Math.PI * 2);
        ctx.globalAlpha = 0.22 + (3 - r) * 0.1;
        ctx.stroke();
      }

      if (sceneSpec.id === 'EVENT_SNIPER') {
        ctx.globalAlpha = 0.65;
        ctx.beginPath();
        ctx.moveTo(-baseR * 1.4, 0);
        ctx.lineTo(baseR * 1.4, 0);
        ctx.moveTo(0, -baseR * 1.4);
        ctx.lineTo(0, baseR * 1.4);
        ctx.stroke();
      } else if (sceneSpec.id === 'EVENT_JACKPOT' || sceneSpec.id === 'EVENT_ROOT_REVERSAL') {
        const rays = 16;
        const rot = this.a11y.settings.reduceMotion ? 0 : elapsed * 0.45;
        ctx.rotate(rot);
        for (let i = 0; i < rays; i++) {
          ctx.rotate((Math.PI * 2) / rays);
          ctx.beginPath();
          ctx.moveTo(baseR * 0.35, 0);
          ctx.lineTo(baseR * 1.45, 0);
          ctx.globalAlpha = 0.25;
          ctx.stroke();
        }
      }
      ctx.restore();

      // Particle Stream
      for (const p of this.particles) {
        if (!this.a11y.settings.reduceMotion) {
          p.x = (p.x + p.vx + 1) % 1;
          p.y = (p.y + p.vy + 1) % 1;
        }
        ctx.beginPath();
        ctx.arc(p.x * w, p.y * h, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = sceneSpec.themeColor || '#35D9FF';
        ctx.globalAlpha = 0.55;
        ctx.fill();
      }
    };

    this.animFrameId = requestAnimationFrame(render);
  }

  stopFullscreenCanvasEffect() {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
  }
}

// ============================================================================
// 9. TRANSITION MANAGER & SCENE MANAGER (Section 6, 7, 15)
// ============================================================================
export class TransitionManager {
  constructor(a11y) {
    this.a11y = a11y;
  }

  async runTransitionGate(labelEn = 'INITIALIZING EVENT SCENE', durationMs = 380) {
    const gateEl = document.getElementById('scene-transition-gate');
    const gateLabel = document.getElementById('scene-transition-label');
    if (!gateEl) return;

    if (gateLabel) gateLabel.textContent = labelEn;
    if (this.a11y.settings.reduceMotion || this.a11y.settings.lowStimulusMode) {
      return;
    }

    gateEl.classList.remove('hidden');
    await new Promise((r) => setTimeout(r, durationMs));
    gateEl.classList.add('hidden');
  }
}

export class SceneManager {
  constructor() {
    this.state = 'MAIN_MONITOR'; // MAIN_MONITOR | EVENT_TRANSITION | FULLSCREEN_EVENT | EVENT_RESULT | RETURN_TRANSITION | EMERGENCY_ALERT
    this.activeSidebarTab = 'OVERVIEW';
    this.activeScreenNumber = 1;
    this.savedSidebarTab = 'OVERVIEW';

    this.a11y = new AccessibilityManager();
    this.audio = new AudioManager(this.a11y);
    this.cameraDirector = new CameraDirector();
    this.priorityManager = new EventPriorityManager();
    this.eventQueue = new EventQueue();
    this.animController = new AnimationController(this.a11y);
    this.transitionManager = new TransitionManager(this.a11y);
    this.zundamonStage = new ZundamonStageController();

    this.autoReturnTimer = null;
  }

  init() {
    this.a11y.applyToDocument();
    this.zundamonStage.renderAvatar();
    this.updateSceneBadge();
  }

  updateSceneBadge() {
    const badge = document.getElementById('top-scene-state-badge');
    if (badge) {
      badge.textContent = this.state;
    }
  }

  switchSidebarTab(tabName) {
    this.activeSidebarTab = tabName;
    const tabs = ['OVERVIEW', 'NETWORK', 'SECURITY', 'ANALYSIS', 'EVENTS', 'SYSTEM'];
    for (const t of tabs) {
      const btn = document.getElementById(`sidebar-tab-btn-${t}`);
      const pane = document.getElementById(`sidebar-tab-pane-${t}`);
      if (btn) {
        if (t === tabName) {
          btn.className =
            'px-2 py-1.5 rounded-md text-[10px] font-mono font-bold bg-[#102A42] text-[#35D9FF] border border-[#35D9FF]/60 shadow-[0_0_10px_rgba(53,217,255,0.22)] transition-all';
        } else {
          btn.className =
            'px-2 py-1.5 rounded-md text-[10px] font-mono font-semibold text-[#9GB4CC] hover:text-white hover:bg-[#091C30] border border-transparent transition-all';
        }
      }
      if (pane) {
        pane.classList.toggle('hidden', t !== tabName);
      }
    }
  }

  /**
   * Triggers a Dedicated Fullscreen Event Scene or Fullscreen Gachapon Scene
   * following the exact state flow:
   * MAIN_MONITOR -> EVENT_TRANSITION -> FULLSCREEN_EVENT -> EVENT_RESULT -> RETURN_TRANSITION -> MAIN_MONITOR
   */
  async launchFullscreenEvent({
    sceneKey = 'EVENT_NORMAL',
    mode = 'EVENT_SCENE', // 'EVENT_SCENE' | 'GACHAPON_SCENE'
    spinData = null,
    effectId = 'EFFECT-01',
    autoReturnMs = 0
  } = {}) {
    if (window.emergencyOverrideActive) return;

    const spec = FULLSCREEN_EVENT_SCENES[sceneKey] || FULLSCREEN_EVENT_SCENES.EVENT_NORMAL;
    if (!this.priorityManager.canPreempt(spec.priority)) {
      this.eventQueue.enqueue({ sceneKey, mode, spinData, effectId, priority: spec.priority });
      return;
    }

    if (this.autoReturnTimer) {
      clearTimeout(this.autoReturnTimer);
      this.autoReturnTimer = null;
    }

    // 1. Save current MAIN_MONITOR state (Earth rotation, camera zoom, active sidebar tab)
    if (this.state === 'MAIN_MONITOR') {
      this.cameraDirector.captureMainMonitorState();
      this.savedSidebarTab = this.activeSidebarTab;
    }

    this.priorityManager.currentActivePriority = spec.priority;

    // 2. EVENT_TRANSITION
    this.state = 'EVENT_TRANSITION';
    this.updateSceneBadge();
    this.cameraDirector.playTransitionZoomIn();
    this.audio.playCyberSe(spec.rank === 'GOLD' ? 'jackpot' : 'transition');
    await this.transitionManager.runTransitionGate(`SCENE TRANSITION // ${spec.title_en}`, 280);

    if (window.emergencyOverrideActive) return;

    // 3. FULLSCREEN_EVENT
    this.state = 'FULLSCREEN_EVENT';
    this.updateSceneBadge();

    const fsOverlay = document.getElementById('fullscreen-scene-container');
    const gachaStage = document.getElementById('fullscreen-gachapon-stage');
    const eventStage = document.getElementById('fullscreen-cinematic-stage');

    if (fsOverlay) fsOverlay.classList.remove('hidden');

    // Update Fullscreen Header & Result Texts
    const titleEnEl = document.getElementById('fs-scene-title-en');
    const titleJaEl = document.getElementById('fs-scene-title-ja');
    const rankBadgeEl = document.getElementById('fs-scene-rank-badge');
    const descJaEl = document.getElementById('fs-scene-desc-ja');
    const effectBadgeEl = document.getElementById('fs-scene-effect-id');

    if (titleEnEl) {
      titleEnEl.textContent = mode === 'GACHAPON_SCENE' ? '3D LUXURY GLASS DOME GACHAPON SCENE' : spec.title_en;
      titleEnEl.style.color = spec.themeColor;
    }
    if (titleJaEl) {
      titleJaEl.textContent =
        mode === 'GACHAPON_SCENE' ? 'ガラポン専用全画面イベントシーン (3D透明ドーム物理抽選)' : spec.title_ja;
    }
    if (rankBadgeEl) {
      rankBadgeEl.textContent = `${spec.rank} CAPSULE // ${spec.id}`;
      rankBadgeEl.style.borderColor = spec.themeColor;
      rankBadgeEl.style.color = spec.themeColor;
    }
    if (effectBadgeEl) {
      const effList = spinData?.selected_effects?.map((e) => `${e.effect_id}: ${e.name_ja}`).join(' + ') || effectId;
      effectBadgeEl.textContent = effList;
    }
    if (descJaEl) {
      descJaEl.textContent = spinData?.zundamon_speech_ja || spec.desc_ja;
    }

    // Update Zundamon expression & costume
    this.zundamonStage.setState({
      expression: spec.zundamonExpression,
      costume: spinData?.zundamon_costume || spec.zundamonCostume,
      speakingDurationMs: 2200
    });

    if (mode === 'GACHAPON_SCENE') {
      if (gachaStage) gachaStage.classList.remove('hidden');
      if (eventStage) eventStage.classList.add('hidden');
      if (window.ThunderhallGachapon3D) {
        window.ThunderhallGachapon3D.triggerSpinAnimation(spec.rank, true);
      }
    } else {
      if (gachaStage) gachaStage.classList.remove('hidden');
      if (eventStage) eventStage.classList.remove('hidden');
      const stageCanvas = document.getElementById('fullscreen-event-stage-canvas');
      this.animController.startFullscreenCanvasEffect(stageCanvas, spec);
      if (window.ThunderhallGachapon3D) {
        window.ThunderhallGachapon3D.triggerSpinAnimation(spec.rank, true);
      }
    }

    // 4. Transition to EVENT_RESULT state after capsule opening
    setTimeout(() => {
      if (this.state === 'FULLSCREEN_EVENT') {
        this.state = 'EVENT_RESULT';
        this.updateSceneBadge();
      }
    }, 1100);

    if (autoReturnMs > 0) {
      this.autoReturnTimer = setTimeout(() => {
        this.returnToMainMonitor();
      }, autoReturnMs);
    }
  }

  /**
   * Executes RETURN_TRANSITION and restores MAIN_MONITOR state without resetting Earth or logs
   */
  async returnToMainMonitor() {
    if (this.autoReturnTimer) {
      clearTimeout(this.autoReturnTimer);
      this.autoReturnTimer = null;
    }

    this.state = 'RETURN_TRANSITION';
    this.updateSceneBadge();
    this.animController.stopFullscreenCanvasEffect();

    await this.transitionManager.runTransitionGate('RETURNING TO MAIN MONITOR', 220);

    const fsOverlay = document.getElementById('fullscreen-scene-container');
    if (fsOverlay) fsOverlay.classList.add('hidden');

    // Restore Earth rotation, camera zoom, and sidebar tab
    this.cameraDirector.restoreMainMonitorState();
    this.switchSidebarTab(this.savedSidebarTab || 'OVERVIEW');

    this.state = 'MAIN_MONITOR';
    this.priorityManager.currentActivePriority = null;
    this.updateSceneBadge();

    // Process next queued event if any
    const nextEvt = this.eventQueue.dequeue();
    if (nextEvt && !window.emergencyOverrideActive) {
      this.launchFullscreenEvent(nextEvt);
    }
  }

  /**
   * Priority #1 Override: Real Disaster / Civil Protection Emergency Screen (Section 14)
   * Immediately aborts all gachapon, fullscreen effects, and entertainment audio in 0ms.
   */
  triggerEmergencyAlertOverride(alertInfo) {
    if (this.autoReturnTimer) {
      clearTimeout(this.autoReturnTimer);
      this.autoReturnTimer = null;
    }
    this.eventQueue.clearAll();
    this.animController.stopFullscreenCanvasEffect();
    this.audio.stopAllImmediately();

    const fsOverlay = document.getElementById('fullscreen-scene-container');
    if (fsOverlay) fsOverlay.classList.add('hidden');

    this.state = 'EMERGENCY_ALERT';
    this.priorityManager.currentActivePriority = 1;
    this.updateSceneBadge();

    this.zundamonStage.setState({
      expression: 'EMERGENCY',
      costume: 'RED_ALERT_COMMANDER_ZUNDAMON',
      speakingDurationMs: 0
    });

    const emModal = document.getElementById('emergency-fullscreen-override');
    if (emModal && alertInfo) {
      emModal.classList.remove('hidden');
      const hEl = document.getElementById('em-fs-headline');
      const dEl = document.getElementById('em-fs-detail');
      const aEl = document.getElementById('em-fs-action');
      if (hEl) hEl.textContent = alertInfo.headline_ja || '【訓練 / SIMULATION】緊急地震速報・国民保護情報';
      if (dEl) {
        dEl.textContent = `対象地域: ${alertInfo.epicenter_or_area_ja || '全国'} ／ 最大震度・規模: ${alertInfo.max_seismic_intensity || '震度6弱'} (${alertInfo.magnitude_or_scale || 'M7.2'})`;
      }
      if (aEl) {
        aEl.textContent =
          alertInfo.protective_action_ja ||
          '直ちに身の安全を確保してください。すべての娯楽・ガチャ演出および効果音を強制停止しています。';
      }
    }
  }

  clearEmergencyAlertOverride() {
    this.audio.clearEmergencyMute();
    const emModal = document.getElementById('emergency-fullscreen-override');
    if (emModal) emModal.classList.add('hidden');
    this.priorityManager.currentActivePriority = null;
    this.state = 'MAIN_MONITOR';
    this.updateSceneBadge();
    this.zundamonStage.setState({
      expression: 'NORMAL',
      costume: 'NORMAL_ZUNDAMON'
    });
  }

  /**
   * Unified 25-Screen Switcher (Section 12)
   */
  openSystemScreen(screenNumber) {
    const spec = ALL_25_SCREENS.find((s) => s.num === Number(screenNumber)) || ALL_25_SCREENS[0];
    this.activeScreenNumber = spec.num;

    const screenSelect = document.getElementById('system-25-screen-select');
    if (screenSelect && String(screenSelect.value) !== String(spec.num)) {
      screenSelect.value = String(spec.num);
    }

    if (spec.type === 'main') {
      this.returnToMainMonitor();
      if (typeof window.setSocLayout === 'function') window.setSocLayout('arena');
      this.switchSidebarTab(spec.tab || 'OVERVIEW');
      return;
    }

    if (spec.type === 'gachapon') {
      this.launchFullscreenEvent({
        sceneKey: 'EVENT_NORMAL',
        mode: 'GACHAPON_SCENE'
      });
      return;
    }

    if (spec.type === 'transition_preview') {
      this.launchFullscreenEvent({
        sceneKey: 'EVENT_JACKPOT',
        mode: 'EVENT_SCENE'
      });
      return;
    }

    if (spec.type === 'emergency') {
      if (typeof window.triggerArenaEmergencyAlert === 'function') {
        window.triggerArenaEmergencyAlert('trigger_drill', 'JMA_EARTHQUAKE_EEW');
      }
      return;
    }

    if (spec.type === 'modal' && spec.modalId) {
      if (typeof window.openPlanMatrixModal === 'function') {
        window.openPlanMatrixModal();
      }
      return;
    }

    if (spec.type === 'sidebar') {
      this.returnToMainMonitor();
      if (typeof window.setSocLayout === 'function') window.setSocLayout('arena');
      this.switchSidebarTab(spec.tab || 'OVERVIEW');
      return;
    }

    if (spec.type === 'module' && spec.modId) {
      this.returnToMainMonitor();
      if (typeof window.onModuleDirectSelect === 'function') {
        window.onModuleDirectSelect(spec.modId);
      }
      return;
    }

    if (spec.type === 'custom_drawer') {
      this.returnToMainMonitor();
      this.switchSidebarTab(spec.tab || 'SYSTEM');
    }
  }
}

export function initThunderhallSceneEngine() {
  const manager = new SceneManager();
  manager.init();
  window.ThunderhallSceneEngine = manager;
  return manager;
}
