import http from 'http';

// ============================================================================
// ZUNDAMON AI COMMENTARY, 6 COSTUMES, VOICEVOX (127.0.0.1:50021) & EMERGENCY ALERT
// Sections 10, 15, 16, 17, 18
// ============================================================================

export type ZundamonCostumeId =
  | 'NORMAL_ZUNDAMON'
  | 'CYBER_OPERATOR_ZUNDAMON'
  | 'TACTICAL_RESPONDER_ZUNDAMON'
  | 'RED_ALERT_COMMANDER_ZUNDAMON'
  | 'GOLD_JACKPOT_FESTIVAL_ZUNDAMON'
  | 'SUPREME_GOLDEN_ZUNDAMON';

export interface ZundamonCostumeSpec {
  costume_id: ZundamonCostumeId;
  name_ja: string;
  name_en: string;
  trigger_condition: string;
  theme_color_hex: string;
  badge_icon: string;
  description_ja: string;
}

export const ZUNDAMON_6_COSTUMES: Record<ZundamonCostumeId, ZundamonCostumeSpec> = {
  NORMAL_ZUNDAMON: {
    costume_id: 'NORMAL_ZUNDAMON',
    name_ja: '通常ずんだもん (Normal)',
    name_en: 'Normal Zundamon',
    trigger_condition: '平時監視・Greenカプセル排出時',
    theme_color_hex: '#10B981',
    badge_icon: '🌿',
    description_ja: '平時のネットワーク監視とやさしい用語解説を担当する基本フォームなのだ！',
  },
  CYBER_OPERATOR_ZUNDAMON: {
    costume_id: 'CYBER_OPERATOR_ZUNDAMON',
    name_ja: 'サイバーオペレーターずんだもん (Cyber Operator)',
    name_en: 'Cyber Operator Zundamon',
    trigger_condition: 'AIスキャン実行中・Blueミニカプセル・偵察検知時',
    theme_color_hex: '#00D2FF',
    badge_icon: '🎧',
    description_ja: '光学バイザーと通信ヘッドセットを装着し、世界の通信ルートを解析するフォームなのだ！',
  },
  TACTICAL_RESPONDER_ZUNDAMON: {
    costume_id: 'TACTICAL_RESPONDER_ZUNDAMON',
    name_ja: 'タクティカル防衛ずんだもん (Tactical Responder)',
    name_en: 'Tactical Responder Zundamon',
    trigger_condition: 'Orangeカプセル・ハニーポット誘導・中脅威対処時',
    theme_color_hex: '#F59E0B',
    badge_icon: '🛡️',
    description_ja: 'イージス戦術ジャケットを纏い、攻撃Botをハニーポットへ誘導する防衛フォームなのだ！',
  },
  RED_ALERT_COMMANDER_ZUNDAMON: {
    costume_id: 'RED_ALERT_COMMANDER_ZUNDAMON',
    name_ja: 'レッドアラート司令官ずんだもん (Red Alert Commander)',
    name_en: 'Red Alert Commander Zundamon',
    trigger_condition: 'Redカプセル・高脅威検知・2名Quorum警戒時',
    theme_color_hex: '#F43F5E',
    badge_icon: '🚨',
    description_ja: '緊急防衛マントを羽織り、高リスク脆弱性検証とQuorumゲートを指揮する司令官フォームなのだ！',
  },
  GOLD_JACKPOT_FESTIVAL_ZUNDAMON: {
    costume_id: 'GOLD_JACKPOT_FESTIVAL_ZUNDAMON',
    name_ja: 'ゴールド祝祭ずんだもん (Gold Jackpot Festival)',
    name_en: 'Gold Jackpot Festival Zundamon',
    trigger_condition: 'Goldカプセル・完全防衛勝利達成時',
    theme_color_hex: '#FFD700',
    badge_icon: '👑',
    description_ja: 'ゴールドカプセル排出と完全防衛勝利を祝うキラキラのフェスティバル衣装なのだ！',
  },
  SUPREME_GOLDEN_ZUNDAMON: {
    costume_id: 'SUPREME_GOLDEN_ZUNDAMON',
    name_ja: '至高の黄金覚醒ずんだもん (Supreme Golden)',
    name_en: 'Supreme Golden Zundamon',
    trigger_condition: 'Core Breach 12段階演出・POTENTIAL_ZERO_DAY実証成功時',
    theme_color_hex: '#FFF380',
    badge_icon: '✨',
    description_ja: '地球コア・ブリーチ成功時のみ顕現する、七色オーラを纏った最高峰の黄金覚醒フォームなのだ！！',
  },
};

export interface SecurityGlossaryCard {
  term_id: string;
  term_en: string;
  term_ja: string;
  easy_explanation_ja: string;
  zundamon_tip_ja: string;
}

export const SECURITY_GLOSSARY_CARDS: SecurityGlossaryCard[] = [
  {
    term_id: 'TERM-SYN-FLOOD',
    term_en: 'SYN Flood',
    term_ja: 'SYNフラッド（接続要求洪水テスト）',
    easy_explanation_ja: '接続の最初の挨拶（SYN）だけを大量に送って、サーバーの受付窓口がいっぱいにならないか確かめる負荷テスト。',
    zundamon_tip_ja: 'お店の予約電話だけかけて切るイタズラみたいな動きなのだ！サンダーホールはすぐ見抜いてブロックするのだ！',
  },
  {
    term_id: 'TERM-RATE-LIMIT',
    term_en: 'Rate Limit',
    term_ja: 'レート制限（回数制限防御）',
    easy_explanation_ja: '1秒間や1分間にアクセスできる回数を制限して、過剰な連続アクセスからシステムを守る仕組み。',
    zundamon_tip_ja: '連打しすぎた相手に「ちょっと待つのだ！（HTTP 429）」ってブレーキをかける安全装置なのだ！',
  },
  {
    term_id: 'TERM-HONEYPOT',
    term_en: 'Honeypot',
    term_ja: 'ハニーポット（おとり防衛区画）',
    easy_explanation_ja: '本物のサーバーそっくりに作られた安全な「おとりの部屋」に攻撃者を誘導し、手口を観察・隔離する仕組み。',
    zundamon_tip_ja: '悪いBotを本物の金庫じゃなくて、観察用の秘密のお部屋（Outer/Inner）へ案内しちゃう作戦なのだ！',
  },
  {
    term_id: 'TERM-ZERO-DAY',
    term_en: 'Zero-Day Candidate',
    term_ja: 'ゼロデイ候補（未知の脆弱性候補）',
    easy_explanation_ja: 'まだ世界の脆弱性辞書（CVE）に登録されていない、新しい弱点の可能性がある挙動（確定ではなく候補として慎重に検証するもの）。',
    zundamon_tip_ja: 'まだ誰も知らないかもしれない新しい弱点のタマゴなのだ！必ず安全なサンドボックスの中で再現テストするのだ！',
  },
  {
    term_id: 'TERM-CVE',
    term_en: 'CVE (Common Vulnerabilities and Exposures)',
    term_ja: 'CVE（共通脆弱性識別子）',
    easy_explanation_ja: '世界中で発見されたソフトウェアの弱点に付けられる「CVE-2024-XXXX」のような世界共通の管理番号。',
    zundamon_tip_ja: '世界共通の「弱点図鑑の番号」なのだ！番号が分かれば対策もすぐ確認できるのだ！',
  },
  {
    term_id: 'TERM-CWE',
    term_en: 'CWE (Common Weakness Enumeration)',
    term_ja: 'CWE（共通脆弱性タイプ一覧）',
    easy_explanation_ja: 'パストラバーサル（CWE-22）やXSS（CWE-79）など、プログラムの弱点の「種類・原因」を分類する番号。',
    zundamon_tip_ja: 'どんな種類のミスなのかを分類するラベルなのだ！',
  },
  {
    term_id: 'TERM-FALSE-POSITIVE',
    term_en: 'False Positive',
    term_ja: 'フォルス・ポジティブ（誤検知）',
    easy_explanation_ja: '最初は危険なサインに見えたが、詳しく検証した結果、実際には無害・安全だったと確認されたもの。',
    zundamon_tip_ja: '火災報知器が湯気に反応しちゃった時みたいに、「調べたら安全だった！」という結果なのだ！正直に記録するのが大事なのだ！',
  },
];

export interface CommentaryLogItem {
  commentary_id: string;
  priority: 'EMERGENCY_OVERRIDE' | 'CRITICAL_SECURITY' | 'GACHAPON_JACKPOT' | 'NORMAL_COMMENTARY';
  original_en: string;
  translated_ja: string;
  zundamon_speech_ja: string;
  costume: ZundamonCostumeId;
  voice_synthesis_mode:
    | 'VOICEVOX_LOCAL_50021'
    | 'PREGENERATED_VOICEVOX_CACHE'
    | 'SUBTITLE_ONLY_FALLBACK'
    | 'MUTED_BY_EMERGENCY_ALERT';
  other_tts_imitation_used: false;
  timestamp: string;
}

// Sanitize untrusted strings so raw payloads are never spoken or injected
export function sanitizeSpeechText(raw: string): string {
  return String(raw || '')
    .replace(/[<>`"'\\;$|&{}[\]\0\r\n]/g, ' ')
    .slice(0, 220)
    .trim();
}

// ============================================================================
// VOICEVOX Local Background Adapter (127.0.0.1:50021 ONLY — Zero Other-TTS Imitation)
// ============================================================================
const VOICEVOX_HOST = '127.0.0.1';
const VOICEVOX_PORT = 50021;

let voicevoxStatus: {
  bind_address: '127.0.0.1:50021';
  external_exposure: false;
  engine_reachable: boolean;
  version: string;
  active_mode: 'VOICEVOX_LOCAL_ENGINE' | 'SUBTITLE_ONLY_FALLBACK';
  other_tts_imitation_prohibited: true;
  speaker_id: number;
  speaker_credit: 'VOICEVOX:ずんだもん';
  last_checked: string;
} = {
  bind_address: '127.0.0.1:50021',
  external_exposure: false,
  engine_reachable: false,
  version: 'SUBTITLE_ONLY_MODE (VOICEVOX OFFLINE)',
  active_mode: 'SUBTITLE_ONLY_FALLBACK',
  other_tts_imitation_prohibited: true,
  speaker_id: 3, // Zundamon Normal speaker ID in VOICEVOX
  speaker_credit: 'VOICEVOX:ずんだもん',
  last_checked: new Date().toISOString(),
};

export function checkLocalVoicevoxHealth(): Promise<typeof voicevoxStatus> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        hostname: VOICEVOX_HOST,
        port: VOICEVOX_PORT,
        path: '/version',
        method: 'GET',
        timeout: 600,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.from(c)));
        res.on('end', () => {
          if (res.statusCode === 200) {
            voicevoxStatus = {
              bind_address: '127.0.0.1:50021',
              external_exposure: false,
              engine_reachable: true,
              version: Buffer.concat(chunks).toString('utf8').replace(/"/g, '').trim() || '0.21.0',
              active_mode: 'VOICEVOX_LOCAL_ENGINE',
              other_tts_imitation_prohibited: true,
              speaker_id: 3,
              speaker_credit: 'VOICEVOX:ずんだもん',
              last_checked: new Date().toISOString(),
            };
          } else {
            voicevoxStatus.engine_reachable = false;
            voicevoxStatus.active_mode = 'SUBTITLE_ONLY_FALLBACK';
            voicevoxStatus.last_checked = new Date().toISOString();
          }
          resolve(voicevoxStatus);
        });
      }
    );
    req.on('error', () => {
      voicevoxStatus.engine_reachable = false;
      voicevoxStatus.active_mode = 'SUBTITLE_ONLY_FALLBACK';
      voicevoxStatus.last_checked = new Date().toISOString();
      resolve(voicevoxStatus);
    });
    req.on('timeout', () => {
      req.destroy();
      voicevoxStatus.engine_reachable = false;
      voicevoxStatus.active_mode = 'SUBTITLE_ONLY_FALLBACK';
      voicevoxStatus.last_checked = new Date().toISOString();
      resolve(voicevoxStatus);
    });
    req.end();
  });
}

// ============================================================================
// Public Emergency Alert System (Section 18 — Priority #1 Override)
// ============================================================================
export type EmergencyAlertType =
  | 'NONE'
  | 'JMA_EARTHQUAKE_EEW'
  | 'JMA_TSUNAMI_WARNING'
  | 'JMA_SEVERE_WEATHER'
  | 'J_ALERT_CIVIL_PROTECTION';

export interface PublicEmergencyAlertState {
  active: boolean;
  is_training_drill: boolean;
  alert_id: string | null;
  alert_type: EmergencyAlertType;
  headline_ja: string;
  headline_en: string;
  epicenter_or_area_ja: string;
  magnitude_or_scale: string;
  max_seismic_intensity: string;
  tsunami_risk_ja: string;
  protective_action_ja: string;
  source_authority: string;
  non_official_disclaimer_ja: 'この配信は公式情報源ではありません。公式情報を確認してください';
  entertainment_effects_suppressed: boolean;
  gachapon_paused: boolean;
  fake_alerts_prohibited_invariant: true;
  issued_at: string | null;
}

let currentEmergencyAlert: PublicEmergencyAlertState = {
  active: false,
  is_training_drill: false,
  alert_id: null,
  alert_type: 'NONE',
  headline_ja: '現在、発令中の気象庁（JMA）緊急地震速報・津波警報・気象特別警報はありません',
  headline_en: 'No active JMA public emergency alerts',
  epicenter_or_area_ja: '--',
  magnitude_or_scale: '--',
  max_seismic_intensity: '--',
  tsunami_risk_ja: 'なし',
  protective_action_ja: '平常通りセキュリティ監視・検証を継続できます。',
  source_authority: '気象庁（JMA）公開防災情報スキーマ準拠モニター (待機中)',
  non_official_disclaimer_ja: 'この配信は公式情報源ではありません。公式情報を確認してください',
  entertainment_effects_suppressed: false,
  gachapon_paused: false,
  fake_alerts_prohibited_invariant: true,
  issued_at: null,
};

let currentCostume: ZundamonCostumeId = 'NORMAL_ZUNDAMON';
let commentaryFeed: CommentaryLogItem[] = [
  {
    commentary_id: 'COM-0001',
    priority: 'NORMAL_COMMENTARY',
    original_en: 'THUNDERHALL Global Cyber Battle Arena initialized. All 3D routes and bots operate in isolated RFC 5737 synthetic space.',
    translated_ja: 'サンダーホール グローバル・サイバー・バトルアリーナ起動完了。全3D経路とBotは隔離されたRFC 5737合成テスト空間で稼働中。',
    zundamon_speech_ja: 'サンダーホール起動完了なのだ！完全隔離モードで安全に検証実況するのだ！',
    costume: 'NORMAL_ZUNDAMON',
    voice_synthesis_mode: 'SUBTITLE_ONLY_FALLBACK',
    other_tts_imitation_used: false,
    timestamp: new Date().toISOString(),
  },
];

export function pushZundamonCommentary(params: {
  priority?: CommentaryLogItem['priority'];
  original_en: string;
  translated_ja: string;
  zundamon_speech_ja: string;
  costume?: ZundamonCostumeId;
}): CommentaryLogItem {
  if (params.costume && !currentEmergencyAlert.active) {
    currentCostume = params.costume;
  }
  const item: CommentaryLogItem = {
    commentary_id: `COM-${String(commentaryFeed.length + 1).padStart(4, '0')}`,
    priority: params.priority || 'NORMAL_COMMENTARY',
    original_en: sanitizeSpeechText(params.original_en),
    translated_ja: sanitizeSpeechText(params.translated_ja),
    zundamon_speech_ja: sanitizeSpeechText(params.zundamon_speech_ja),
    costume: currentCostume,
    voice_synthesis_mode: currentEmergencyAlert.active
      ? 'MUTED_BY_EMERGENCY_ALERT'
      : voicevoxStatus.engine_reachable
        ? 'VOICEVOX_LOCAL_50021'
        : 'SUBTITLE_ONLY_FALLBACK',
    other_tts_imitation_used: false,
    timestamp: new Date().toISOString(),
  };
  commentaryFeed.unshift(item);
  if (commentaryFeed.length > 40) {
    commentaryFeed = commentaryFeed.slice(0, 40);
  }
  return item;
}

export function triggerEmergencyAlertOverride(params: {
  action: 'trigger_drill' | 'clear';
  alert_type?: EmergencyAlertType;
  area_ja?: string;
  intensity?: string;
}): PublicEmergencyAlertState {
  if (params.action === 'clear') {
    currentEmergencyAlert = {
      active: false,
      is_training_drill: false,
      alert_id: null,
      alert_type: 'NONE',
      headline_ja: '現在、発令中の気象庁（JMA）緊急地震速報・津波警報・気象特別警報はありません',
      headline_en: 'No active JMA public emergency alerts',
      epicenter_or_area_ja: '--',
      magnitude_or_scale: '--',
      max_seismic_intensity: '--',
      tsunami_risk_ja: 'なし',
      protective_action_ja: '緊急警報オーバーライドを解除しました。通常監視へ復帰します。',
      source_authority: '気象庁（JMA）公開防災情報スキーマ準拠モニター (待機中)',
      non_official_disclaimer_ja: 'この配信は公式情報源ではありません。公式情報を確認してください',
      entertainment_effects_suppressed: false,
      gachapon_paused: false,
      fake_alerts_prohibited_invariant: true,
      issued_at: null,
    };
    currentCostume = 'NORMAL_ZUNDAMON';
    pushZundamonCommentary({
      priority: 'NORMAL_COMMENTARY',
      original_en: 'Emergency alert drill cleared. Resuming normal cyber arena monitoring.',
      translated_ja: '緊急警報訓練モードを終了し、通常のサイバー監視へ復帰しました。',
      zundamon_speech_ja: '訓練アラートを解除したのだ。安全確認ヨシ！通常監視に戻るのだ。',
      costume: 'NORMAL_ZUNDAMON',
    });
    return currentEmergencyAlert;
  }

  const aType: EmergencyAlertType = params.alert_type || 'JMA_EARTHQUAKE_EEW';
  const nowIso = new Date().toISOString();

  const presets: Record<
    Exclude<EmergencyAlertType, 'NONE'>,
    {
      headline_ja: string;
      headline_en: string;
      area_ja: string;
      mag: string;
      intensity: string;
      tsunami: string;
      action_ja: string;
      source: string;
    }
  > = {
    JMA_EARTHQUAKE_EEW: {
      headline_ja: '【訓練・テスト表示 / TEST DRILL】気象庁 緊急地震速報（警報）— 強い揺れに備えてください',
      headline_en: '[TEST DRILL — NOT A REAL EMERGENCY] JMA Earthquake Early Warning',
      area_ja: params.area_ja || '茨城県沖・関東地方全域（訓練データ）',
      mag: 'M6.8 (訓練値)',
      intensity: params.intensity || '震度5強 (訓練値)',
      tsunami: '津波の心配なし（訓練データ）',
      action_ja: '【最優先安全行動】机の下など安全な場所に身を隠し、頭部を守ってください。すべてのガチャ・派手な演出は自動停止されました。',
      source: '気象庁（JMA）公開防災情報スキーマ準拠 (ローカル訓練検証モード)',
    },
    JMA_TSUNAMI_WARNING: {
      headline_ja: '【訓練・テスト表示 / TEST DRILL】気象庁 津波警報 — 沿岸部・川沿いから直ちに高台へ避難',
      headline_en: '[TEST DRILL — NOT A REAL EMERGENCY] JMA Tsunami Warning',
      area_ja: params.area_ja || '太平洋沿岸東部（訓練データ）',
      mag: '予想高さ 3m (訓練値)',
      intensity: '津波警報 (訓練値)',
      tsunami: '津波警報発令中（訓練データ）',
      action_ja: '【最優先安全行動】海岸や河口付近から直ちに離れ、高台や避難ビルへ避難してください。全エンターテインメント演出を停止しています。',
      source: '気象庁（JMA）公開防災情報スキーマ準拠 (ローカル訓練検証モード)',
    },
    JMA_SEVERE_WEATHER: {
      headline_ja: '【訓練・テスト表示 / TEST DRILL】気象庁 大雨特別警報 — 命を守る最善の行動をとってください',
      headline_en: '[TEST DRILL — NOT A REAL EMERGENCY] JMA Emergency Weather Warning',
      area_ja: params.area_ja || '九州北部・中国地方（訓練データ）',
      mag: '特別警報級 (訓練値)',
      intensity: '警戒レベル5相当 (訓練値)',
      tsunami: '高潮・氾濫警戒（訓練データ）',
      action_ja: '【最優先安全行動】周囲の状況を確認し、浸水・土砂災害から命を守る行動を最優先してください。',
      source: '気象庁（JMA）公開防災情報スキーマ準拠 (ローカル訓練検証モード)',
    },
    J_ALERT_CIVIL_PROTECTION: {
      headline_ja: '【訓練・テスト表示 / TEST DRILL】気象庁防災情報テスト（J-Alertは調査結果提示・未実装）',
      headline_en: '[TEST DRILL — NOT A REAL EMERGENCY] Public Safety Drill Notice',
      area_ja: params.area_ja || '対象地域全域（訓練データ）',
      mag: '防災訓練データ (訓練値)',
      intensity: '最優先緊急情報 (訓練値)',
      tsunami: '安全確保訓練（訓練データ）',
      action_ja: '【最優先安全行動】この配信は公式情報源ではありません。公式情報を確認してください。',
      source: '気象庁公開防災情報スキーマ準拠 (J-Alertは一般公開API不在のため未実装)',
    },
  };

  const chosen = presets[aType === 'NONE' ? 'JMA_EARTHQUAKE_EEW' : aType];

  currentEmergencyAlert = {
    active: true,
    is_training_drill: true, // Strictly marked as training drill so it never fabricates a false real emergency
    alert_id: `EMERG-DRILL-${Date.now().toString().slice(-6)}`,
    alert_type: aType,
    headline_ja: chosen.headline_ja,
    headline_en: chosen.headline_en,
    epicenter_or_area_ja: chosen.area_ja,
    magnitude_or_scale: chosen.mag,
    max_seismic_intensity: chosen.intensity,
    tsunami_risk_ja: chosen.tsunami,
    protective_action_ja: chosen.action_ja,
    source_authority: chosen.source,
    non_official_disclaimer_ja: 'この配信は公式情報源ではありません。公式情報を確認してください',
    entertainment_effects_suppressed: true,
    gachapon_paused: true,
    fake_alerts_prohibited_invariant: true,
    issued_at: nowIso,
  };

  currentCostume = 'RED_ALERT_COMMANDER_ZUNDAMON';
  return currentEmergencyAlert;
}

export function getZundamonAndAlertSnapshot() {
  return {
    current_costume: currentCostume,
    costume_spec: ZUNDAMON_6_COSTUMES[currentCostume],
    all_6_costumes: ZUNDAMON_6_COSTUMES,
    voicevox_engine: voicevoxStatus,
    glossary_cards: SECURITY_GLOSSARY_CARDS,
    commentary_feed: commentaryFeed.slice(0, 15),
    emergency_alert: currentEmergencyAlert,
  };
}
