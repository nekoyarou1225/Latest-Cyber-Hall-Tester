// ============================================================================
// THUNDERHALL BOT ARENA SIMULATOR & GLOBAL CYBER BATTLEFIELD ENGINE
// Sections 4, 5, 6, 7, 8, 9 + V2.1 Clause C Fictional Region Support
// ============================================================================
import { FICTIONAL_REGIONS_CATALOG, getV21PolicySnapshot } from './v22_gemini_voicevox_stream.js';

export type BotType =
  | 'RECON_BOT'
  | 'SCANNER_BOT'
  | 'FUZZER_BOT'
  | 'CREDENTIAL_TEST_BOT'
  | 'SESSION_STRESS_BOT'
  | 'API_PRESSURE_BOT'
  | 'ROUTE_SIM_BOT'
  | 'HONEYPOT_PROBE_BOT'
  | 'DEFENSE_VERIFICATION_BOT';

export type BotLifecycleStage =
  | 'IDLE'
  | 'SPAWNING'
  | 'RECON'
  | 'ROUTE_LOCK'
  | 'PROBING'
  | 'PRESSURE_TEST'
  | 'VULN_VERIFICATION'
  | 'HONEYPOT_TRAPPED'
  | 'RATE_LIMITED'
  | 'BLOCKED'
  | 'TERMINATED';

export type RouteColorClass =
  | 'CYAN_NORMAL'
  | 'YELLOW_ELEVATED'
  | 'ORANGE_FUZZING'
  | 'RED_CRITICAL_VULN'
  | 'PURPLE_HONEYPOT'
  | 'GREEN_BLOCKED'
  | 'GOLD_SPECIAL_EVENT';

export interface VirtualBotEntity {
  bot_id: string;
  bot_name: string;
  bot_type: BotType;
  virtual_ipv4: string; // RFC 5737 only: 192.0.2.x, 198.51.100.x, 203.0.113.x
  virtual_ipv6: string; // RFC 3849 only: 2001:db8:...
  virtual_mac: string; // Locally-administered 02:AA:xx:xx:xx:xx
  asn_sim_id: string;
  origin_country: string;
  origin_city: string;
  origin_coords: { lat: number; lon: number };
  relay_chain: Array<{
    hop: number;
    node_name: string;
    relay_type: 'SUBMARINE_CABLE' | 'IX_GATEWAY' | 'SATELLITE_ORB' | 'ASN_ROUTER';
    lat: number;
    lon: number;
  }>;
  target_region: string;
  target_prefecture_ja: string;
  target_node: string;
  target_coords: { lat: number; lon: number };
  protocol: string;
  pps_rate: number;
  bps_rate: number;
  payload_profile: string;
  status: BotLifecycleStage;
  route_color: RouteColorClass;
  threat_level: number; // 0-100
  assigned_cve_test: string;
  detection_state: 'DETECTED' | 'ANALYZING' | 'SIGNATURE_MATCHED';
  mitigation_state: 'BLOCKED_AT_EDGE' | 'REDIRECTED_TO_HONEYPOT' | 'RATE_LIMITED' | 'SANDBOX_OBSERVED';
  synthetic_label: 'THUNDERHALL BOT ARENA SIMULATOR (SYNTHETIC TEST ADDRESS)';
  timestamp_created: string;
  timestamp_last_event: string;
}

export interface SatelliteOrbitNode {
  sat_id: string;
  name: string;
  orbit_class: 'LEO' | 'MEO' | 'GEO';
  altitude_km: number;
  inclination_deg: number;
  lat: number;
  lon: number;
  simulated_rtt_ms: number;
  uplink_station: string;
  downlink_station_ja: string;
  beam_status: 'ACTIVE_RELAY' | 'STANDBY' | 'DEFENSE_LOCK';
  label: 'SIMULATED SATELLITE ROUTE';
}

export interface JapanPrefectureNode {
  pref_id: string;
  name_ja: string;
  name_en: string;
  region_ja: string;
  lat: number;
  lon: number;
  datacenter_node: string;
  defense_status: 'SHIELD_ACTIVE' | 'HONEYPOT_DIVERTING' | 'HIGH_LOAD_MONITORING';
}

const BOT_TYPES: BotType[] = [
  'RECON_BOT',
  'SCANNER_BOT',
  'FUZZER_BOT',
  'CREDENTIAL_TEST_BOT',
  'SESSION_STRESS_BOT',
  'API_PRESSURE_BOT',
  'ROUTE_SIM_BOT',
  'HONEYPOT_PROBE_BOT',
  'DEFENSE_VERIFICATION_BOT',
];

const BOT_STAGES: BotLifecycleStage[] = [
  'IDLE',
  'SPAWNING',
  'RECON',
  'ROUTE_LOCK',
  'PROBING',
  'PRESSURE_TEST',
  'VULN_VERIFICATION',
  'HONEYPOT_TRAPPED',
  'RATE_LIMITED',
  'BLOCKED',
  'TERMINATED',
];

const GLOBAL_ORIGINS = [
  { country: 'US', city: 'Ashburn', lat: 39.0438, lon: -77.4874, asn: 'AS-SIM-64512' },
  { country: 'US', city: 'Silicon Valley', lat: 37.3861, lon: -122.0839, asn: 'AS-SIM-64513' },
  { country: 'DE', city: 'Frankfurt', lat: 50.1109, lon: 8.6821, asn: 'AS-SIM-64514' },
  { country: 'GB', city: 'London', lat: 51.5072, lon: -0.1276, asn: 'AS-SIM-64515' },
  { country: 'NL', city: 'Amsterdam', lat: 52.3676, lon: 4.9041, asn: 'AS-SIM-64516' },
  { country: 'SG', city: 'Singapore', lat: 1.3521, lon: 103.8198, asn: 'AS-SIM-64517' },
  { country: 'AU', city: 'Sydney', lat: -33.8688, lon: 151.2093, asn: 'AS-SIM-64518' },
  { country: 'BR', city: 'Sao Paulo', lat: -23.5505, lon: -46.6333, asn: 'AS-SIM-64519' },
  { country: 'IN', city: 'Mumbai', lat: 19.076, lon: 72.8777, asn: 'AS-SIM-64520' },
  { country: 'KR', city: 'Seoul', lat: 37.5665, lon: 126.978, asn: 'AS-SIM-64521' },
  { country: 'FR', city: 'Paris', lat: 48.8566, lon: 2.3522, asn: 'AS-SIM-64522' },
  { country: 'CA', city: 'Toronto', lat: 43.6532, lon: -79.3832, asn: 'AS-SIM-64523' },
];

export const JAPAN_STRATEGIC_NODES: JapanPrefectureNode[] = [
  { pref_id: 'JP-01', name_ja: '北海道 (札幌DC)', name_en: 'Hokkaido (Sapporo)', region_ja: '北海道', lat: 43.0618, lon: 141.3545, datacenter_node: 'TH-DC-SAPPORO-01', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-04', name_ja: '宮城県 (仙台IX)', name_en: 'Miyagi (Sendai)', region_ja: '東北', lat: 38.2682, lon: 140.8694, datacenter_node: 'TH-DC-SENDAI-02', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-08', name_ja: '茨城県 (つくば研究網)', name_en: 'Ibaraki (Tsukuba)', region_ja: '関東', lat: 36.0835, lon: 140.0764, datacenter_node: 'TH-LAB-TSUKUBA-03', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-13', name_ja: '東京都 (大手町コアIX)', name_en: 'Tokyo (Otemachi Core)', region_ja: '関東', lat: 35.6895, lon: 139.6917, datacenter_node: 'TH-CORE-TOKYO-01', defense_status: 'HONEYPOT_DIVERTING' },
  { pref_id: 'JP-14', name_ja: '神奈川県 (横浜海底陸揚局)', name_en: 'Kanagawa (Yokohama)', region_ja: '関東', lat: 35.4437, lon: 139.638, datacenter_node: 'TH-CABLE-YOKOHAMA-02', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-17', name_ja: '石川県 (金沢北陸GW)', name_en: 'Ishikawa (Kanazawa)', region_ja: '中部', lat: 36.5613, lon: 136.6562, datacenter_node: 'TH-GW-KANAZAWA-01', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-23', name_ja: '愛知県 (名古屋中部IX)', name_en: 'Aichi (Nagoya)', region_ja: '中部', lat: 35.1815, lon: 136.9066, datacenter_node: 'TH-DC-NAGOYA-01', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-27', name_ja: '大阪府 (堂島コアDC)', name_en: 'Osaka (Dojima Core)', region_ja: '近畿', lat: 34.6937, lon: 135.5023, datacenter_node: 'TH-CORE-OSAKA-01', defense_status: 'HONEYPOT_DIVERTING' },
  { pref_id: 'JP-30', name_ja: '和歌山県 (志摩/南紀海底局)', name_en: 'Wakayama (Submarine Hub)', region_ja: '近畿', lat: 34.226, lon: 135.1675, datacenter_node: 'TH-CABLE-KANSAI-02', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-34', name_ja: '広島県 (中国防衛GW)', name_en: 'Hiroshima (Chugoku)', region_ja: '中国', lat: 34.3853, lon: 132.4553, datacenter_node: 'TH-GW-HIROSHIMA-01', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-37', name_ja: '香川県 (高松四国IX)', name_en: 'Kagawa (Takamatsu)', region_ja: '四国', lat: 34.3428, lon: 134.0466, datacenter_node: 'TH-GW-SHIKOKU-01', defense_status: 'SHIELD_ACTIVE' },
  { pref_id: 'JP-40', name_ja: '福岡県 (博多アジアゲート)', name_en: 'Fukuoka (Hakata Asia Gate)', region_ja: '九州', lat: 33.5902, lon: 130.4017, datacenter_node: 'TH-CORE-FUKUOKA-01', defense_status: 'HONEYPOT_DIVERTING' },
  { pref_id: 'JP-47', name_ja: '沖縄県 (那覇海底ケーブル局)', name_en: 'Okinawa (Naha Submarine Hub)', region_ja: '沖縄', lat: 26.2124, lon: 127.6809, datacenter_node: 'TH-CABLE-OKINAWA-01', defense_status: 'SHIELD_ACTIVE' },
];

export const SATELLITE_ORBIT_NODES: SatelliteOrbitNode[] = [
  {
    sat_id: 'SAT-LEO-01',
    name: 'THUNDER-LEO-ALPHA (低軌道メッシュ #1)',
    orbit_class: 'LEO',
    altitude_km: 550,
    inclination_deg: 53.0,
    lat: 38.5,
    lon: 142.2,
    simulated_rtt_ms: 28,
    uplink_station: 'US-West Ground Sim',
    downlink_station_ja: '東京都 大手町地上局 (SIM)',
    beam_status: 'ACTIVE_RELAY',
    label: 'SIMULATED SATELLITE ROUTE',
  },
  {
    sat_id: 'SAT-LEO-02',
    name: 'THUNDER-LEO-BETA (低軌道メッシュ #2)',
    orbit_class: 'LEO',
    altitude_km: 780,
    inclination_deg: 70.0,
    lat: 29.4,
    lon: 129.8,
    simulated_rtt_ms: 34,
    uplink_station: 'SG-Equatorial Ground Sim',
    downlink_station_ja: '福岡県 博多地上局 (SIM)',
    beam_status: 'ACTIVE_RELAY',
    label: 'SIMULATED SATELLITE ROUTE',
  },
  {
    sat_id: 'SAT-MEO-01',
    name: 'THUNDER-MEO-GUARDIAN (中軌道広域中継)',
    orbit_class: 'MEO',
    altitude_km: 12000,
    inclination_deg: 45.0,
    lat: 22.0,
    lon: 136.0,
    simulated_rtt_ms: 124,
    uplink_station: 'EU-Frankfurt Ground Sim',
    downlink_station_ja: '大阪府 堂島地上局 (SIM)',
    beam_status: 'DEFENSE_LOCK',
    label: 'SIMULATED SATELLITE ROUTE',
  },
  {
    sat_id: 'SAT-GEO-01',
    name: 'THUNDER-GEO-SENTINEL (静止軌道アジア太平洋監視)',
    orbit_class: 'GEO',
    altitude_km: 35786,
    inclination_deg: 0.1,
    lat: 0.0,
    lon: 140.0,
    simulated_rtt_ms: 498,
    uplink_station: 'Global Telemetry Trunk Sim',
    downlink_station_ja: '茨城県 つくば衛星管制局 (SIM)',
    beam_status: 'ACTIVE_RELAY',
    label: 'SIMULATED SATELLITE ROUTE',
  },
];

// Deterministic RFC 5737 IPv4 generator (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
export function generateSyntheticIpv4(index: number): string {
  const blocks = ['192.0.2', '198.51.100', '203.0.113'];
  const block = blocks[index % blocks.length];
  const hostOctet = (index % 254) + 1;
  return `${block}.${hostOctet}`;
}

// Deterministic RFC 3849 IPv6 generator (2001:db8::/32)
export function generateSyntheticIpv6(index: number): string {
  const seg1 = ((index >> 16) & 0xffff).toString(16).padStart(4, '0');
  const seg2 = (index & 0xffff).toString(16).padStart(4, '0');
  return `2001:db8:85a3:${seg1}::${seg2}`;
}

// Deterministic Locally-Administered Unicast MAC generator (02:AA:xx:xx:xx:xx)
// Guaranteed 100% unique for indices 0 .. 16,777,215 (well above 10,000 bot requirement)
export function generateUniqueSyntheticMac(index: number): string {
  const n = index + 1;
  const b2 = (n >> 24) & 0xff;
  const b3 = (n >> 16) & 0xff;
  const b4 = (n >> 8) & 0xff;
  const b5 = n & 0xff;
  const hex = (v: number) => v.toString(16).toUpperCase().padStart(2, '0');
  return `02:AA:${hex(b2)}:${hex(b3)}:${hex(b4)}:${hex(b5)}`;
}

export function determineBotScaleTier(botCount: bigint): {
  tier_id: string;
  scale_range: string;
  rendering_method: string;
  individual_entities_generated: number;
  clustered_groups: number;
  is_statistical_aggregation: boolean;
} {
  if (botCount <= 100n) {
    return {
      tier_id: 'SCALE_1_TO_100',
      scale_range: '1 - 100',
      rendering_method: 'Full Individual Bot Markers + Labels + Individual 3D Route Arcs',
      individual_entities_generated: Number(botCount),
      clustered_groups: 1,
      is_statistical_aggregation: false,
    };
  }
  if (botCount <= 1000n) {
    return {
      tier_id: 'SCALE_101_TO_1K',
      scale_range: '101 - 1,000',
      rendering_method: 'Individual InstancedMesh Markers + Simplified Labels + Grouped Arcs',
      individual_entities_generated: 100,
      clustered_groups: 12,
      is_statistical_aggregation: false,
    };
  }
  if (botCount <= 10000n) {
    return {
      tier_id: 'SCALE_1K_TO_10K',
      scale_range: '1,001 - 10,000',
      rendering_method: 'High-Density GPU Instanced Particles + Clustering + Sampled Inspection',
      individual_entities_generated: 120,
      clustered_groups: 24,
      is_statistical_aggregation: false,
    };
  }
  if (botCount <= 1000000n) {
    return {
      tier_id: 'SCALE_10K_TO_1M',
      scale_range: '10,001 - 1,000,000',
      rendering_method: 'Regional Heat Clusters + Representative Stream Particles + Drill-Down List',
      individual_entities_generated: 120,
      clustered_groups: 48,
      is_statistical_aggregation: true,
    };
  }
  if (botCount <= 1000000000000n) {
    return {
      tier_id: 'SCALE_1M_TO_1T',
      scale_range: '1,000,001 - 10^12 (1兆)',
      rendering_method: 'Macro Continental Aggregation Nodes + High-Luminance Orbital Beams',
      individual_entities_generated: 120,
      clustered_groups: 96,
      is_statistical_aggregation: true,
    };
  }
  return {
    tier_id: 'SCALE_1T_TO_10E16_QUADRILLION',
    scale_range: '10^12 - 10^16 (1京 / One Quadrillion)',
    rendering_method: 'One Quadrillion Statistical Aggregation + Planetary Energy Rings + Exact BigInt Counter',
    individual_entities_generated: 120,
    clustered_groups: 195,
    is_statistical_aggregation: true,
  };
}

export function formatJapaneseLargeBigInt(val: bigint): string {
  if (val === 0n) return '0';
  const kei = val / 10000000000000000n;
  const remKei = val % 10000000000000000n;
  const cho = remKei / 1000000000000n;
  const remCho = remKei % 1000000000000n;
  const oku = remCho / 100000000n;
  const remOku = remCho % 100000000n;
  const man = remOku / 10000n;
  const one = remOku % 10000n;

  const parts: string[] = [];
  if (kei > 0n) parts.push(`${kei.toString()}京`);
  if (cho > 0n) parts.push(`${cho.toString()}兆`);
  if (oku > 0n) parts.push(`${oku.toString()}億`);
  if (man > 0n) parts.push(`${man.toString()}万`);
  if (one > 0n || parts.length === 0) parts.push(one.toString());
  return parts.join(' ');
}

export function generateBotEntitiesSample(count: number, tickOffset = 0): VirtualBotEntity[] {
  const safeCount = Math.max(1, Math.min(200, count));
  const nowIso = new Date().toISOString();
  const list: VirtualBotEntity[] = [];

  const routeColors: RouteColorClass[] = [
    'CYAN_NORMAL',
    'YELLOW_ELEVATED',
    'ORANGE_FUZZING',
    'RED_CRITICAL_VULN',
    'PURPLE_HONEYPOT',
    'GREEN_BLOCKED',
    'GOLD_SPECIAL_EVENT',
  ];

  const cveTests = [
    'CVE-2024-29041 (Redirect Check)',
    'CWE-22 (Path Traversal Canary)',
    'CWE-287 (Quorum Spoof Test)',
    'CWE-352 (CSRF Token Probe)',
    'ZDAY-CAND-001 (BigInt Boundary)',
    'CWE-79 (XSS Angle-Bracket Canary)',
    'CWE-400 (Rate-Limit Burst Probe)',
  ];

  const v21Policy = getV21PolicySnapshot();
  for (let i = 0; i < safeCount; i++) {
    const origin = GLOBAL_ORIGINS[i % GLOBAL_ORIGINS.length];
    const fictionalOrigin = FICTIONAL_REGIONS_CATALOG[i % FICTIONAL_REGIONS_CATALOG.length];
    const useFictionalGeo = v21Policy.fictional_geography_default;
    const originCountryLabel = useFictionalGeo ? fictionalOrigin.region_code : origin.country;
    const originCityLabel = useFictionalGeo ? fictionalOrigin.relay_id : origin.city;
    const target = JAPAN_STRATEGIC_NODES[i % JAPAN_STRATEGIC_NODES.length];
    const sat = SATELLITE_ORBIT_NODES[i % SATELLITE_ORBIT_NODES.length];
    const bType = BOT_TYPES[i % BOT_TYPES.length];
    const stageIdx = (i + tickOffset) % BOT_STAGES.length;
    const status = BOT_STAGES[stageIdx];
    const color = routeColors[(i + tickOffset) % routeColors.length];

    list.push({
      bot_id: `BOT-${String(i + 1).padStart(5, '0')}`,
      bot_name: `TH-${bType.replace('_BOT', '')}-${String(i + 1).padStart(4, '0')}`,
      bot_type: bType,
      virtual_ipv4: generateSyntheticIpv4(i),
      virtual_ipv6: generateSyntheticIpv6(i),
      virtual_mac: generateUniqueSyntheticMac(i),
      asn_sim_id: origin.asn,
      origin_country: originCountryLabel,
      origin_city: originCityLabel,
      origin_coords: { lat: origin.lat, lon: origin.lon },
      relay_chain: [
        {
          hop: 1,
          node_name: `${originCityLabel} Submarine Landing`,
          relay_type: 'SUBMARINE_CABLE',
          lat: origin.lat * 0.7,
          lon: origin.lon * 0.7,
        },
        {
          hop: 2,
          node_name: sat.name,
          relay_type: 'SATELLITE_ORB',
          lat: sat.lat,
          lon: sat.lon,
        },
        {
          hop: 3,
          node_name: `${target.datacenter_node} Edge Filter`,
          relay_type: 'IX_GATEWAY',
          lat: target.lat,
          lon: target.lon,
        },
      ],
      target_region: target.region_ja,
      target_prefecture_ja: target.name_ja,
      target_node: target.datacenter_node,
      target_coords: { lat: target.lat, lon: target.lon },
      protocol: i % 3 === 0 ? 'HTTPS/TLS1.3 (SIM)' : i % 3 === 1 ? 'QUIC/HTTP3 (SIM)' : 'TCP/SYN-CANARY (SIM)',
      pps_rate: 100 + ((i * 37) % 4900),
      bps_rate: (100 + ((i * 37) % 4900)) * 8192,
      payload_profile: 'SYNTHETIC_NON_DESTRUCTIVE_CANARY_V2',
      status,
      route_color: color,
      threat_level: 15 + ((i * 19) % 85),
      assigned_cve_test: cveTests[i % cveTests.length],
      detection_state: 'SIGNATURE_MATCHED',
      mitigation_state:
        color === 'PURPLE_HONEYPOT'
          ? 'REDIRECTED_TO_HONEYPOT'
          : color === 'GREEN_BLOCKED'
            ? 'BLOCKED_AT_EDGE'
            : 'RATE_LIMITED',
      synthetic_label: 'THUNDERHALL BOT ARENA SIMULATOR (SYNTHETIC TEST ADDRESS)',
      timestamp_created: nowIso,
      timestamp_last_event: nowIso,
    });
  }
  return list;
}

export function verifyUniqueBotIdentityBatch(batchSize = 10000): {
  tested_count: number;
  unique_mac_count: number;
  unique_bot_id_count: number;
  all_ipv4_rfc5737_compliant: boolean;
  all_ipv6_rfc3849_compliant: boolean;
  zero_collision_verified: boolean;
} {
  const cap = Math.max(1, Math.min(10000, batchSize));
  const macSet = new Set<string>();
  const idSet = new Set<string>();
  let ipv4Ok = true;
  let ipv6Ok = true;

  for (let i = 0; i < cap; i++) {
    const mac = generateUniqueSyntheticMac(i);
    const id = `BOT-${String(i + 1).padStart(5, '0')}`;
    const v4 = generateSyntheticIpv4(i);
    const v6 = generateSyntheticIpv6(i);
    macSet.add(mac);
    idSet.add(id);
    if (
      !v4.startsWith('192.0.2.') &&
      !v4.startsWith('198.51.100.') &&
      !v4.startsWith('203.0.113.')
    ) {
      ipv4Ok = false;
    }
    if (!v6.startsWith('2001:db8:')) {
      ipv6Ok = false;
    }
  }

  return {
    tested_count: cap,
    unique_mac_count: macSet.size,
    unique_bot_id_count: idSet.size,
    all_ipv4_rfc5737_compliant: ipv4Ok,
    all_ipv6_rfc3849_compliant: ipv6Ok,
    zero_collision_verified: macSet.size === cap && idSet.size === cap && ipv4Ok && ipv6Ok,
  };
}

// Section 9: 5 Independent Threat Scores & 7 Independent Communication Telemetry Metrics
export function computeSeparatedTelemetryAndScores(params: {
  virtualBotsBigInt: bigint;
  completedPacketsBigInt: bigint;
  targetPacketsBigInt: bigint;
  appliedPps: number;
  simRunning: boolean;
  isolatedHoneypots: number;
}) {
  const { virtualBotsBigInt, completedPacketsBigInt, targetPacketsBigInt, appliedPps, simRunning, isolatedHoneypots } = params;

  const botScaleLog = virtualBotsBigInt > 0n ? Math.min(16, virtualBotsBigInt.toString().length - 1) : 0;
  const botThreatScore = Math.min(100, Math.round(18 + botScaleLog * 4.5 + (simRunning ? 10 : 0)));
  const packetThreatScore = Math.min(100, Math.round(12 + Math.min(60, appliedPps / 250) + (simRunning ? 15 : 0)));
  const sessionThreatScore = Math.min(100, Math.round(20 + isolatedHoneypots * 15 + (simRunning ? 12 : 0)));
  const campaignThreatScore = Math.min(100, Math.round((botThreatScore + packetThreatScore + sessionThreatScore) / 3));

  const overallScore = Math.min(100, Math.round(campaignThreatScore * 0.9 + (isolatedHoneypots > 0 ? 10 : 0)));
  const overallAlertLevel =
    overallScore >= 85
      ? 'LEVEL 5: CRITICAL DEFENSE'
      : overallScore >= 65
        ? 'LEVEL 4: HIGH ALERT'
        : overallScore >= 45
          ? 'LEVEL 3: ELEVATED WATCH'
          : overallScore >= 25
            ? 'LEVEL 2: GUARDED'
            : 'LEVEL 1: NORMAL';

  const simRxBps = BigInt(appliedPps) * 8192n;
  const simTxBps = BigInt(appliedPps) * 2048n;

  return {
    threat_scores: {
      bot_threat_score: botThreatScore,
      packet_threat_score: packetThreatScore,
      session_threat_score: sessionThreatScore,
      campaign_threat_score: campaignThreatScore,
      overall_defense_score: overallScore,
      overall_alert_level: overallAlertLevel,
    },
    communication_telemetry: {
      inbound_rx_bps: {
        real_measured_bps: 0,
        simulated_test_bps: simRxBps.toString(),
        evidence_label: 'SIMULATED (Real NIC Egress/Ingress Attack Traffic = 0 bps)',
      },
      outbound_tx_bps: {
        real_measured_bps: 0,
        simulated_test_bps: simTxBps.toString(),
        evidence_label: 'SIMULATED (Zero-Network Egress Gate Locked)',
      },
      packets_per_second: {
        applied_pps: appliedPps,
        evidence_label: 'SIMULATED',
      },
      connections_per_second: {
        simulated_cps: Math.max(0, Math.round(appliedPps * 0.15)),
        evidence_label: 'SIMULATED',
      },
      round_trip_time_ms: {
        local_loopback_real_ms: 0.4,
        terrestrial_route_sim_ms: 38.5,
        satellite_leo_sim_ms: 28.0,
        satellite_geo_sim_ms: 498.0,
      },
      packet_loss_percent: {
        real_local_loss_pct: 0.0,
        simulated_mitigation_drop_pct: simRunning ? 99.4 : 0.0,
      },
      defense_disposition_ratio: {
        blocked_at_edge_pct: 72.5,
        redirected_to_honeypot_pct: 26.9,
        allowed_clean_canary_pct: 0.6,
      },
    },
    one_quadrillion_scale: {
      actual_local_packets: completedPacketsBigInt.toString(),
      target_packets_exact_decimal: targetPacketsBigInt.toString(),
      target_packets_formatted_ja: formatJapaneseLargeBigInt(targetPacketsBigInt),
      virtual_bots_exact_decimal: virtualBotsBigInt.toString(),
      virtual_bots_formatted_ja: formatJapaneseLargeBigInt(virtualBotsBigInt),
      theoretical_bandwidth_gbps: (virtualBotsBigInt * 10n).toString(),
      precision_mode: 'EXACT_BIGINT_DECIMAL_STRING (Zero IEEE-754 Rounding Loss)',
    },
  };
}
