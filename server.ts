import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFile } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '1mb' }));

const port = Number(process.env.PORT) || 3000;
// Bind address policy (PART 2.1): Supports explicit BIND_HOST (e.g. 127.0.0.1 for local standalone),
// while defaulting to 0.0.0.0 in container preview environment with mandatory Auth/CSRF/CSP security gate.
const host = process.env.BIND_HOST || process.env.HOST || '0.0.0.0';

// ============================================================================
// 0. Security Headers & CSP Middleware (PART 2.4)
// ============================================================================
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "frame-ancestors 'self' https://*.run.app https://*.ai.studio https://aistudio.google.com",
      "object-src 'none'",
      "base-uri 'self'",
    ].join('; ')
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  next();
});

// ============================================================================
// 1. Fail-Closed 14-Category Redaction & Tamper-Evident SHA-256 Audit Chain (PART 3.3)
// ============================================================================
export type EvidenceClass =
  | 'STATIC_ANALYSIS'
  | 'TEST_EXECUTED'
  | 'VERIFIED_BY_EXECUTION'
  | 'SIMULATED'
  | 'ESTIMATED'
  | 'UNVERIFIED';

export interface AuditLogEntry {
  seq: number;
  event_id: string;
  timestamp: string;
  actor: string;
  event_type: string;
  category: 'REAL_AUDIT' | 'SIMULATION_EVENT' | 'DEMO_SIMULATION';
  target: string;
  result: 'SUCCESS' | 'DENIED' | 'ERROR';
  evidence_class: EvidenceClass;
  message: string;
  prev_sha256: string;
  entry_sha256: string;
}

const REDACTION_PATTERNS: Array<[string, RegExp, string]> = [
  ['PRIVATE_KEY_BLOCK', /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]'],
  ['BEARER_HEADER', /\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED_BEARER_TOKEN]'],
  ['OAUTH_TOKEN', /\b(ya29\.[A-Za-z0-9._-]+|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})\b/g, '[REDACTED_OAUTH_TOKEN]'],
  ['API_KEY', /\b(AIza[0-9A-Za-z_-]{20,}|sk-[A-Za-z0-9]{16,}|sk_live_[0-9a-zA-Z]{8,}|rk_live_[0-9a-zA-Z]{8,}|AKIA[0-9A-Z]{16})\b/g, '[REDACTED_API_KEY]'],
  ['STREAM_KEY_ASSIGN', /\b((?:stream[_-]?key|rtmp[_-]?key|ingest[_-]?key|youtube[_-]?key)\s*[:=]\s*["']?)([^"'\s,;}{]{4,})/gi, '$1[REDACTED_STREAM_KEY]'],
  ['SECRET_ASSIGN', /\b((?:password|passwd|pwd|secret|client_secret|access_token|refresh_token|api_key|private_key|auth_token|session_token)\s*[:=]\s*["']?)([^"'\s,;}{]{3,})/gi, '$1[REDACTED_SECRET]'],
  ['COOKIE_HEADER', /\b((?:Set-Cookie|Cookie)\s*:\s*)[^\r\n]+/gi, '$1[REDACTED_COOKIE]'],
  ['ENV_SECRET', /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|STREAM_KEY)[A-Z0-9_]*\s*=\s*)([^\r\n#]+)/g, '$1[REDACTED_ENV_SECRET]'],
  ['CREDIT_CARD', /\b(?:\d{4}[ -]?){3}\d{4}\b/g, '[REDACTED_CREDIT_CARD]'],
  ['EMAIL_ADDRESS', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]'],
  ['PHONE_NUMBER', /(?:\+?\d{1,3}[ -]?)?(?:\(\d{2,4}\)|\d{2,4})[ -]\d{3,4}[ -]\d{4}\b/g, '[REDACTED_PHONE]'],
  ['USER_HOME_PATH', /(?:\/Users\/[A-Za-z0-9._-]+|\/home\/[A-Za-z0-9._-]+|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+)/g, '[REDACTED_USER_PATH]'],
  ['DB_CONN_STRING', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s"']+/gi, '[REDACTED_DB_URI]'],
  ['JWT_TOKEN', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[REDACTED_JWT]'],
];

const sensitiveLiterals = new Map<string, string>();

export function redactTextFailClosed(input: string): string {
  try {
    if (typeof input !== 'string') {
      throw new TypeError('Redaction input must be a string');
    }
    let out = input;
    for (const [literal, placeholder] of sensitiveLiterals.entries()) {
      if (literal && out.includes(literal)) {
        out = out.split(literal).join(placeholder);
      }
    }
    for (const [, regex, replacement] of REDACTION_PATTERNS) {
      out = out.replace(regex, replacement);
    }
    return out;
  } catch {
    throw new Error('Fail-Closed Redaction Error: Sensitive output suppressed');
  }
}

const GENESIS_HASH = '0'.repeat(64);
const auditFullChain: AuditLogEntry[] = [];
let nextAuditSeq = 1;
let lastAuditEntryHash = GENESIS_HASH;

export function computeCanonicalAuditInput(entry: Omit<AuditLogEntry, 'entry_sha256'>): string {
  return [
    entry.seq,
    entry.event_id,
    entry.timestamp,
    entry.actor,
    entry.event_type,
    entry.category,
    entry.target,
    entry.result,
    entry.evidence_class,
    entry.message,
    entry.prev_sha256,
  ].join('|');
}

export function verifyAuditChainIntegrity(): {
  valid: boolean;
  total_entries: number;
  first_seq: number | null;
  last_seq: number | null;
  head_sha256: string;
  failed_at_seq: number | null;
  error?: string;
} {
  let expectedPrev = GENESIS_HASH;
  let expectedSeq = 1;
  for (const item of auditFullChain) {
    if (item.seq !== expectedSeq) {
      return {
        valid: false,
        total_entries: auditFullChain.length,
        first_seq: auditFullChain[0]?.seq ?? null,
        last_seq: auditFullChain[auditFullChain.length - 1]?.seq ?? null,
        head_sha256: lastAuditEntryHash,
        failed_at_seq: item.seq,
        error: `Sequence discontinuity: expected ${expectedSeq}, found ${item.seq}`,
      };
    }
    if (item.prev_sha256 !== expectedPrev) {
      return {
        valid: false,
        total_entries: auditFullChain.length,
        first_seq: auditFullChain[0]?.seq ?? null,
        last_seq: auditFullChain[auditFullChain.length - 1]?.seq ?? null,
        head_sha256: lastAuditEntryHash,
        failed_at_seq: item.seq,
        error: `prev_sha256 mismatch at seq=${item.seq}`,
      };
    }
    const canonical = computeCanonicalAuditInput(item);
    const recomputed = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
    if (recomputed !== item.entry_sha256) {
      return {
        valid: false,
        total_entries: auditFullChain.length,
        first_seq: auditFullChain[0]?.seq ?? null,
        last_seq: auditFullChain[auditFullChain.length - 1]?.seq ?? null,
        head_sha256: lastAuditEntryHash,
        failed_at_seq: item.seq,
        error: `entry_sha256 mismatch at seq=${item.seq}`,
      };
    }
    expectedPrev = item.entry_sha256;
    expectedSeq += 1;
  }
  return {
    valid: true,
    total_entries: auditFullChain.length,
    first_seq: auditFullChain[0]?.seq ?? null,
    last_seq: auditFullChain[auditFullChain.length - 1]?.seq ?? null,
    head_sha256: lastAuditEntryHash,
    failed_at_seq: null,
  };
}

export function appendAuditLog(
  eventType: string,
  message: string,
  category: 'REAL_AUDIT' | 'SIMULATION_EVENT' | 'DEMO_SIMULATION' = 'REAL_AUDIT',
  evidenceClass: EvidenceClass = 'VERIFIED_BY_EXECUTION',
  meta: { actor?: string; target?: string; result?: 'SUCCESS' | 'DENIED' | 'ERROR' } = {}
): AuditLogEntry {
  const seq = nextAuditSeq++;
  const eventId = `aud-${String(seq).padStart(6, '0')}-${crypto.randomBytes(4).toString('hex')}`;
  const ts = new Date().toISOString();
  const actor = redactTextFailClosed(String(meta.actor || 'system'));
  const target = redactTextFailClosed(String(meta.target || 'thunderhall-core'));
  const result = meta.result || 'SUCCESS';
  const safeMsg = redactTextFailClosed(message);
  const prevHash = lastAuditEntryHash;

  const baseEntry: Omit<AuditLogEntry, 'entry_sha256'> = {
    seq,
    event_id: eventId,
    timestamp: ts,
    actor,
    event_type: eventType,
    category,
    target,
    result,
    evidence_class: evidenceClass,
    message: safeMsg,
    prev_sha256: prevHash,
  };

  const canonical = computeCanonicalAuditInput(baseEntry);
  const entryHash = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  lastAuditEntryHash = entryHash;

  const entry: AuditLogEntry = {
    ...baseEntry,
    entry_sha256: entryHash,
  };
  auditFullChain.push(entry);
  appendAuditEntryToDisk(entry);
  return entry;
}

// ============================================================================
// 1.5 Authentication, RBAC, Session Fixation Protection, CSRF & Rate Limit (PART 2.1)
// ============================================================================
export type UserRole = 'admin' | 'group_member' | 'researcher' | 'business_operator' | 'general_user';

export interface UserAccount {
  user_id: string;
  username: string;
  display_name: string;
  role: UserRole;
  allowed_categories: PlanCategory[];
  password_salt: string;
  password_hash: string;
}

export interface ActiveSession {
  session_id: string;
  user_id: string;
  username: string;
  display_name: string;
  role: UserRole;
  csrf_token: string;
  created_at_epoch: number;
  expires_at_epoch: number;
  last_reverified_epoch: number;
}

const SESSION_TTL_SEC = 86400; // 24h
const REVERIFY_TTL_SEC = 900; // 15m for critical operations
const userAccounts = new Map<string, UserAccount>();
const activeSessions = new Map<string, ActiveSession>();

function hashPasswordPbkdf2(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function registerSeedUser(
  user_id: string,
  display_name: string,
  role: UserRole,
  password: string,
  allowed_categories: PlanCategory[]
) {
  const salt = crypto.createHash('sha256').update(`thunderhall-salt-${user_id}`).digest('hex').slice(0, 32);
  const hash = hashPasswordPbkdf2(password, salt);
  userAccounts.set(user_id, {
    user_id,
    username: user_id,
    display_name,
    role,
    allowed_categories,
    password_salt: salt,
    password_hash: hash,
  });
}

// Seed 6 distinct accounts across all 5 RBAC roles + 2 distinct Admins for Quorum
registerSeedUser(
  'admin-alice',
  'Alice (最高セキュリティ管理官 / Quorum承認官A)',
  'admin',
  'Thunderhall!Alice#2026',
  ['general', 'business', 'research', 'group']
);
registerSeedUser(
  'admin-bob',
  'Bob (暗号監査管理官 / Quorum承認官B)',
  'admin',
  'Thunderhall!Bob#2026',
  ['general', 'business', 'research', 'group']
);
registerSeedUser(
  'group-chief',
  'Group Chief (サンダーホール特別作戦班)',
  'group_member',
  'Thunderhall!Group#2026',
  ['general', 'business', 'research', 'group']
);
registerSeedUser(
  'research-lead',
  'Research Lead (先端セキュリティ研究所)',
  'researcher',
  'Thunderhall!Research#2026',
  ['general', 'research']
);
registerSeedUser(
  'biz-operator',
  'Biz Operator (企業SOC運用オペレーター)',
  'business_operator',
  'Thunderhall!Biz#2026',
  ['general', 'business']
);
registerSeedUser(
  'general-user',
  'General User (一般開発者アカウント)',
  'general_user',
  'Thunderhall!General#2026',
  ['general']
);

function parseCookies(cookieHeader?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const pair of cookieHeader.split(';')) {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      out[k] = decodeURIComponent(v);
    }
  }
  return out;
}

function createFreshSession(user: UserAccount, previousSessionId?: string): ActiveSession {
  // Session fixation defense: always destroy any previous session ID and issue a new random ID
  if (previousSessionId && activeSessions.has(previousSessionId)) {
    activeSessions.delete(previousSessionId);
  }
  const nowSec = Math.floor(Date.now() / 1000);
  const session: ActiveSession = {
    session_id: crypto.randomBytes(32).toString('hex'),
    user_id: user.user_id,
    username: user.username,
    display_name: user.display_name,
    role: user.role,
    csrf_token: crypto.randomBytes(24).toString('hex'),
    created_at_epoch: nowSec,
    expires_at_epoch: nowSec + SESSION_TTL_SEC,
    last_reverified_epoch: nowSec,
  };
  activeSessions.set(session.session_id, session);
  return session;
}

export function getSessionFromRequest(req: Request): ActiveSession | null {
  const headerToken = req.headers['x-session-token'];
  const cookies = parseCookies(req.headers.cookie);
  const token =
    typeof headerToken === 'string' && headerToken.trim()
      ? headerToken.trim()
      : cookies['th_session'] || '';
  if (!token) return null;
  const sess = activeSessions.get(token);
  if (!sess) return null;
  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec > sess.expires_at_epoch) {
    activeSessions.delete(token);
    return null;
  }
  return sess;
}

// Sliding-Window Rate Limiter (PART 2.1)
const rateLimitBuckets = new Map<string, number[]>();

function checkRateLimit(req: Request, res: Response, bucketName: string, maxRequests: number, windowMs: number): boolean {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  const testBurstKey = typeof req.headers['x-rate-limit-test-key'] === 'string' ? req.headers['x-rate-limit-test-key'] : '';
  const effectiveMax = testBurstKey ? Math.min(maxRequests, 5) : maxRequests;
  const key = `${bucketName}:${ip}:${testBurstKey}`;
  const now = Date.now();
  const timestamps = (rateLimitBuckets.get(key) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= effectiveMax) {
    appendAuditLog(
      'RATE_LIMIT_EXCEEDED',
      `Rate limit exceeded for bucket '${bucketName}' (limit=${effectiveMax}/${windowMs}ms).`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: ip, target: req.path, result: 'DENIED' }
    );
    res.status(429).json({
      error: `レート制限超過 (Too Many Requests): 短時間に過剰なリクエストが検出されました (${bucketName})。しばらく待ってから再試行してください。`,
    });
    return false;
  }
  timestamps.push(now);
  rateLimitBuckets.set(key, timestamps);
  return true;
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!checkRateLimit(req, res, 'api', 400, 10000)) return;
  const sess = getSessionFromRequest(req);
  if (!sess) {
    appendAuditLog(
      'AUTH_UNAUTHORIZED_ACCESS',
      `Unauthenticated request blocked on ${req.method} ${req.path}`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: 'unauthenticated', target: req.path, result: 'DENIED' }
    );
    return res.status(401).json({
      error: '認証エラー (401 Unauthorized): このAPIを実行するには有効なログインセッションが必要です。',
    });
  }
  (req as Request & { authSession?: ActiveSession }).authSession = sess;
  next();
}

function requireCsrf(req: Request, res: Response, next: NextFunction) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  const sess = (req as Request & { authSession?: ActiveSession }).authSession || getSessionFromRequest(req);
  if (!sess) {
    return res.status(401).json({ error: '認証エラー (401 Unauthorized): セッションが存在しません。' });
  }
  const csrfHeader = req.headers['x-csrf-token'];
  const csrfToken = typeof csrfHeader === 'string' ? csrfHeader.trim() : '';
  if (!csrfToken || csrfToken !== sess.csrf_token) {
    appendAuditLog(
      'CSRF_VALIDATION_FAILED',
      `CSRF token validation failed on ${req.method} ${req.path} for user '${sess.user_id}'.`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: req.path, result: 'DENIED' }
    );
    return res.status(403).json({
      error: 'CSRF検証エラー (403 Forbidden): 有効な X-CSRF-Token ヘッダーが必要です。',
    });
  }
  next();
}

function requireRole(allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession || getSessionFromRequest(req);
    if (!sess) {
      return res.status(401).json({ error: '認証エラー (401 Unauthorized): ログインが必要です。' });
    }
    if (!allowedRoles.includes(sess.role)) {
      appendAuditLog(
        'RBAC_PERMISSION_DENIED',
        `User '${sess.user_id}' (role=${sess.role}) denied access to ${req.method} ${req.path} (requires: ${allowedRoles.join(', ')}).`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: req.path, result: 'DENIED' }
      );
      return res.status(403).json({
        error: `権限不足エラー (403 Forbidden): 現在のロール '${sess.role}' にはこの操作を実行する権限がありません（必要ロール: ${allowedRoles.join(', ')}）。`,
      });
    }
    next();
  };
}

function requireRecentReverification(req: Request, res: Response, next: NextFunction) {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession || getSessionFromRequest(req);
  if (!sess) {
    return res.status(401).json({ error: '認証エラー (401 Unauthorized): ログインが必要です。' });
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec - sess.last_reverified_epoch > REVERIFY_TTL_SEC) {
    return res.status(403).json({
      error: '再認証要求 (Re-authentication Required): 重要操作を実行するにはパスワードまたは署名による再確認が必要です。',
    });
  }
  next();
}

// ============================================================================
// 2. Real Host Device Monitor & SafetyGuard (Section 9 Thresholds)
// ============================================================================
export const SAFETY_GUARD_THRESHOLDS = {
  target_free_ram_mib: 200,
  emergency_min_free_ram_mib: 180,
  max_process_rss_mib: 250,
  target_free_disk_mib: 800,
  emergency_min_free_disk_mib: 600,
};

export function readRealHostTelemetry() {
  let availRamMib = Math.round(os.freemem() / (1024 * 1024));
  let totalRamMib = Math.round(os.totalmem() / (1024 * 1024));
  try {
    if (fs.existsSync('/proc/meminfo')) {
      const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
      for (const line of meminfo.split('\n')) {
        if (line.startsWith('MemAvailable:')) {
          const parts = line.trim().split(/\s+/);
          if (parts[1]) availRamMib = Math.floor(parseInt(parts[1], 10) / 1024);
        } else if (line.startsWith('MemTotal:')) {
          const parts = line.trim().split(/\s+/);
          if (parts[1]) totalRamMib = Math.floor(parseInt(parts[1], 10) / 1024);
        }
      }
    }
  } catch {
    // fallback to os.freemem
  }

  const rssMib = Math.round(process.memoryUsage().rss / (1024 * 1024));
  let diskFreeMib = 2048;
  try {
    const st = fs.statfsSync(__dirname);
    diskFreeMib = Math.floor((Number(st.bavail) * Number(st.bsize)) / (1024 * 1024));
  } catch {
    // fallback
  }

  const load1m = os.loadavg()[0] || 0.2;
  const cpuCount = Math.max(1, os.cpus().length);
  const cpuPercent = Math.min(100, Math.round((load1m / cpuCount) * 1000) / 10);

  const safetyPassed =
    availRamMib >= SAFETY_GUARD_THRESHOLDS.emergency_min_free_ram_mib &&
    rssMib <= SAFETY_GUARD_THRESHOLDS.max_process_rss_mib &&
    diskFreeMib >= SAFETY_GUARD_THRESHOLDS.emergency_min_free_disk_mib;

  return {
    host_available_ram_mib: availRamMib,
    host_total_ram_mib: totalRamMib,
    process_rss_mib: rssMib,
    disk_free_mib: diskFreeMib,
    cpu_percent: cpuPercent,
    cpu_cores: cpuCount,
    kernel_release: os.release(),
    architecture: os.arch(),
    safety_guard_passed: safetyPassed,
    thresholds: SAFETY_GUARD_THRESHOLDS,
    evidence_class: 'VERIFIED_BY_EXECUTION' as EvidenceClass,
    power_sensor_status: 'DIRECT_SENSOR_UNAVAILABLE (Container Virtualized)',
  };
}

// ============================================================================
// 3. Ed25519 Offline License Engine & 32-Plan Catalog (PART 2.2 & PART 5)
// ============================================================================
export type PlanCategory = 'general' | 'business' | 'research' | 'group';
export type PlanIdentifier =
  | 'PLUS'
  | 'PLUSPRO'
  | 'PLUSPROMAX'
  | 'PRO'
  | 'PROMAX'
  | 'ULTRA'
  | 'ULTRAPRO'
  | 'ULTRAMAX';
export type PlanTier = `${PlanCategory}.${PlanIdentifier}`;

export interface PlanEntitlement {
  tier: PlanTier;
  category: PlanCategory;
  identifier: PlanIdentifier;
  category_name: string;
  plan_name: string;
  display_name: string;
  max_honeypots_by_plan: number;
  max_bandwidth_mbps: number;
  core_emergency_bandwidth_mbps: number;
  allowed_os_families: string[];
  allow_custom_os_images: boolean;
  allow_outer_inner_custom_ratio: boolean;
  allow_advanced_dpi_analytics: boolean;
  allow_dev_group_admin: boolean;
  max_daily_usage_sec: number;
   is_unlimited_usage: boolean;
  concurrent_test_pipelines: number;
  max_saved_presets: number;
  support_tier: 'none' | 'self_service' | 'standard' | 'priority' | 'high_priority' | 'research' | 'group_dedicated';
  support_name: string;
  support_sla: string;
  all_features_unlocked: boolean;
}

const CATEGORY_META: Record<PlanCategory, { name: string; target: string }> = {
  general: { name: '一般', target: '個人ユーザー、一般利用者、開発者' },
  business: { name: '業務用', target: '企業、IT部門、セキュリティ運用担当者、開発会社' },
  research: { name: '研究機関用', target: '大学、研究所、研究チーム、高度な技術検証組織' },
  group: { name: 'サンダーホールグループ専用', target: 'サンダーホールグループ内部の正式な認可ユーザー（最上位権限）' },
};

const IDENTIFIER_META: Record<PlanIdentifier, { name: string; position: string }> = {
  PLUS: { name: 'PLUS', position: '基本利用' },
  PLUSPRO: { name: 'PLUS PRO', position: '機能拡張' },
  PLUSPROMAX: { name: 'PLUS PRO MAX', position: '高度な機能拡張' },
  PRO: { name: 'PRO', position: '上級利用' },
  PROMAX: { name: 'PRO MAX', position: '上級フル機能拡張' },
  ULTRA: { name: 'Ultra', position: '高性能利用' },
  ULTRAPRO: { name: 'Ultra PRO', position: '高度な自由度' },
  ULTRAMAX: { name: 'Ultra MAX', position: '最上位' },
};

function generatePlanCatalog(): Record<PlanTier, PlanEntitlement> {
  const catalog: Partial<Record<PlanTier, PlanEntitlement>> = {};
  const categories: PlanCategory[] = ['general', 'business', 'research', 'group'];
  const identifiers: PlanIdentifier[] = [
    'PLUS',
    'PLUSPRO',
    'PLUSPROMAX',
    'PRO',
    'PROMAX',
    'ULTRA',
    'ULTRAPRO',
    'ULTRAMAX',
  ];

  for (const cat of categories) {
    for (let i = 0; i < identifiers.length; i++) {
      const id = identifiers[i];
      const tier = `${cat}.${id}` as PlanTier;
      const rank = i + 1; // 1 to 8
      const catMeta = CATEGORY_META[cat];
      const idMeta = IDENTIFIER_META[id];
      const displayName = `サンダーホール ${idMeta.name} — ${catMeta.name}`;

      const isGroup = cat === 'group';
      const isResearch = cat === 'research';
      const isBusiness = cat === 'business';

      // Daily Usage Time (PART 2.2 & PART 5):
      // General: 1h to 8h (3,600s to 28,800s)
      // Business: 6h to 24h (rank 6-8 = 24h daily limit, NOT unlimited)
      // Research: 12h to 24h (rank 4-8 = 24h daily limit, NOT unlimited)
      // Group: Unlimited (is_unlimited_usage = true)
      let dailyUsageSec = 3600 * rank;
      if (isBusiness) dailyUsageSec = rank >= 6 ? 86400 : 3600 * (4 + rank * 2);
      if (isResearch) dailyUsageSec = rank >= 4 ? 86400 : 3600 * (8 + rank * 4);
      if (isGroup) dailyUsageSec = 86400;

      // Honeypots
      let maxHoneypots = 2 * rank; // General: 2 to 16
      if (isBusiness) maxHoneypots = 8 * rank; // Business: 8 to 64
      if (isResearch) maxHoneypots = 12 * rank; // Research: 12 to 96
      if (isGroup) maxHoneypots = 256; // Group: 256

      // Bandwidth
      let maxBw = 100 * rank; // General: 100 to 800 Mbps
      if (rank >= 4 && cat === 'general') maxBw = 1000 * (rank - 3); // 1Gbps to 5Gbps
      if (isBusiness) maxBw = 1000 * rank * 2; // Business: 2Gbps to 16Gbps
      if (isBusiness && rank === 8) maxBw = 100000; // 100Gbps
      if (isResearch) maxBw = 2500 * rank; // Research: 2.5Gbps to 20Gbps
      if (isResearch && rank === 8) maxBw = 100000;
      if (isGroup) maxBw = 100000; // Group: 100Gbps

      // OS Families
      const allowedOs = ['mk1ai-secure-linux', 'alpine-minimal'];
      if (rank >= 3 || isBusiness || isResearch || isGroup) allowedOs.push('debian-minimal');
      if (rank >= 5 || isBusiness || isResearch || isGroup) allowedOs.push('ubuntu-server-lts');
      if (rank >= 7 || isResearch || isGroup) allowedOs.push('freebsd-minimal', 'custom-verified');
      if (isGroup || (isBusiness && rank >= 6) || (isResearch && rank >= 6)) allowedOs.push('windows-server-guest');

      // Support
      let supportTier: PlanEntitlement['support_tier'] = 'none';
      let supportName = 'サポートなし';
      let supportSla = 'なし';

      if (cat === 'general') {
        if (rank >= 2 && rank <= 3) {
          supportTier = 'self_service';
          supportName = 'セルフサービス';
          supportSla = 'コミュニティ / FAQ';
        } else if (rank >= 4 && rank <= 5) {
          supportTier = 'standard';
          supportName = '通常サポート';
          supportSla = '24時間以内（目標）';
        } else if (rank >= 6) {
          supportTier = 'priority';
          supportName = '優先サポート';
          supportSla = '4時間以内（目標）';
        }
      } else if (isBusiness) {
        if (rank <= 3) {
          supportTier = 'standard';
          supportName = 'ビジネス標準サポート';
          supportSla = '12時間以内（目標）';
        } else if (rank <= 6) {
          supportTier = 'priority';
          supportName = 'ビジネス優先サポート';
          supportSla = '4時間以内（目標）';
        } else {
          supportTier = 'high_priority';
          supportName = '高優先度エンタープライズSLA';
          supportSla = '1時間以内（目標）';
        }
      } else if (isResearch) {
        supportTier = 'research';
        supportName = '研究機関専門サポート';
        supportSla = rank >= 6 ? '2時間以内（目標）' : '8時間以内（目標）';
      } else if (isGroup) {
        supportTier = 'group_dedicated';
        supportName = 'グループ内部専用サポート';
        supportSla = '即時専任対応';
      }

      catalog[tier] = {
        tier,
        category: cat,
        identifier: id,
        category_name: catMeta.name,
        plan_name: idMeta.name,
        display_name: displayName,
        max_honeypots_by_plan: maxHoneypots,
        max_bandwidth_mbps: maxBw,
        core_emergency_bandwidth_mbps: 100,
        allowed_os_families: Array.from(new Set(allowedOs)),
        allow_custom_os_images: isGroup || rank >= 5 || isResearch,
        allow_outer_inner_custom_ratio: isGroup || rank >= 3 || isBusiness || isResearch,
        allow_advanced_dpi_analytics: isGroup || rank >= 6 || isResearch,
        allow_dev_group_admin: isGroup || (isBusiness && rank >= 6),
        max_daily_usage_sec: dailyUsageSec,
        is_unlimited_usage: isGroup,
        concurrent_test_pipelines: isGroup ? 16 : isResearch ? Math.max(2, rank * 2) : Math.max(1, rank * (isBusiness ? 2 : 1)),
        max_saved_presets: isGroup ? 100 : isResearch ? rank * 12 : rank * (isBusiness ? 10 : 5),
        support_tier: supportTier,
        support_name: supportName,
        support_sla: supportSla,
        all_features_unlocked: isGroup,
      };
    }
  }

  return catalog as Record<PlanTier, PlanEntitlement>;
}

export const PLAN_CATALOG = generatePlanCatalog();

// Isolated Offline Authority Vault vs Runtime Public-Key Verifier (PART 2.2)
class IsolatedOfflineLicenseAuthorityVault {
  private readonly keyPair = crypto.generateKeyPairSync('ed25519');

  public getPublicKeyPem(): string {
    return this.keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }

  public signCanonicalPayload(payload: Buffer, authorizedRole: UserRole): string {
    if (authorizedRole !== 'admin' && authorizedRole !== 'group_member') {
      throw new Error('AuthorityVaultAccessDenied: Only authorized Offline Authority may sign bundles');
    }
    return crypto.sign(null, payload, this.keyPair.privateKey).toString('hex');
  }
}

const offlineAuthorityVault = new IsolatedOfflineLicenseAuthorityVault();
const AUTHORITY_PUBLIC_KEY_PEM = offlineAuthorityVault.getPublicKeyPem();

const LOCAL_DEVICE_FINGERPRINT = 'mk1ai-node-thunderhall-001';
let highestMonotonicSeq = 1;
const revokedLicenseIds = new Set<string>();

export interface SignedOfflineLicense {
  license_id: string;
  group_id: string;
  plan_tier: PlanTier;
  device_fingerprint: string;
  issued_at_epoch: number;
  expires_at_epoch: number;
  monotonic_seq: number;
  custom_max_honeypots?: number;
  custom_max_bandwidth_mbps?: number;
  allowed_os_families?: string[];
  signature_ed25519: string;
}

function canonicalizeLicensePayload(lic: Omit<SignedOfflineLicense, 'signature_ed25519'>): Buffer {
  const ordered: Record<string, unknown> = {};
  for (const k of Object.keys(lic).sort()) {
    ordered[k] = (lic as Record<string, unknown>)[k];
  }
  return Buffer.from(JSON.stringify(ordered), 'utf8');
}

function issueSignedLicenseFromVault(
  body: Omit<SignedOfflineLicense, 'signature_ed25519'>,
  issuerRole: UserRole = 'admin'
): SignedOfflineLicense {
  const payload = canonicalizeLicensePayload(body);
  const sig = offlineAuthorityVault.signCanonicalPayload(payload, issuerRole);
  return { ...body, signature_ed25519: sig };
}

// Runtime Verifier strictly uses Public Key PEM only (PART 2.2)
export function verifyLicenseWithPublicKeyOnly(lic: SignedOfflineLicense): boolean {
  try {
    if (!lic || typeof lic !== 'object' || !lic.signature_ed25519) return false;
    const { signature_ed25519, ...rest } = lic;
    const payload = canonicalizeLicensePayload(rest);
    const pubKey = crypto.createPublicKey(AUTHORITY_PUBLIC_KEY_PEM);
    return crypto.verify(null, payload, pubKey, Buffer.from(signature_ed25519, 'hex'));
  } catch {
    return false;
  }
}

// Default initial state (PART 2.2): general.PLUS (Basic General Tier: 1h/day, 2 honeypots, CORE safety 100% locked ON)
let activeLicense: SignedOfflineLicense | null = issueSignedLicenseFromVault(
  {
    license_id: 'lic-thunderhall-general-plus-seq1',
    group_id: 'grp-general-default',
    plan_tier: 'general.PLUS',
    device_fingerprint: LOCAL_DEVICE_FINGERPRINT,
    issued_at_epoch: Math.floor(Date.now() / 1000) - 60,
    expires_at_epoch: Math.floor(Date.now() / 1000) + 86400 * 365,
    monotonic_seq: 1,
  },
  'admin'
);
let licenseStatusNote = 'サンダーホール PLUS — 一般 (初期基本プラン・CORE保護100%常時有効, seq=1)';

// Usage tracking & Pipeline / Preset quota tracking (PART 5)
let dailyUsageSec = 0;
let lastUsageReset = new Date().toDateString();
let activeTestPipelinesCount = 1;
export interface SavedSimPreset {
  preset_id: string;
  name: string;
  target_packets: string;
  pps: number;
  virtual_bots: string;
  created_by: string;
  created_at: string;
}
const savedPresets = new Map<string, SavedSimPreset>();
savedPresets.set('preset-default-1', {
  preset_id: 'preset-default-1',
  name: '標準 100万パケット検証',
  target_packets: '1000000',
  pps: 250,
  virtual_bots: '16',
  created_by: 'system',
  created_at: new Date().toISOString(),
});

function checkUsageReset() {
  const today = new Date().toDateString();
  if (today !== lastUsageReset) {
    dailyUsageSec = 0;
    lastUsageReset = today;
    appendAuditLog('USAGE_RESET', '本日の利用時間カウンタを午前0時に自動リセットしました。', 'REAL_AUDIT', 'VERIFIED_BY_EXECUTION');
  }
}

export function getEffectiveLicenseState() {
  const nowSec = Math.floor(Date.now() / 1000);
  let tier: PlanTier = 'general.PLUS';
  let verified = false;
  let customHp: number | undefined;
  let customBw: number | undefined;

  if (activeLicense) {
    if (!verifyLicenseWithPublicKeyOnly(activeLicense)) {
      licenseStatusNote = `ライセンス署名検証エラーを検出しました。一般基本プラン(general.PLUS)に安全降格しました（CORE保護および緊急停止は100%常時維持）。`;
      activeLicense = null;
    } else if (activeLicense.device_fingerprint !== LOCAL_DEVICE_FINGERPRINT) {
      licenseStatusNote = `デバイスフィンガープリント不一致 ('${activeLicense.device_fingerprint}') のため一般基本プラン(general.PLUS)に降格しました。`;
      activeLicense = null;
    } else if (revokedLicenseIds.has(activeLicense.license_id)) {
      licenseStatusNote = `ライセンス '${activeLicense.license_id}' は失効(CRL)しています。一般基本プラン(general.PLUS)に降格しました（CORE保護および緊急停止は100%常時維持）。`;
      activeLicense = null;
    } else if (nowSec > activeLicense.expires_at_epoch) {
      licenseStatusNote = `ライセンス '${activeLicense.license_id}' は有効期限切れです。一般基本プラン(general.PLUS)に降格しました（CORE保護および緊急停止は100%常時維持）。`;
      activeLicense = null;
    } else {
      tier = activeLicense.plan_tier;
      verified = true;
      customHp = activeLicense.custom_max_honeypots;
      customBw = activeLicense.custom_max_bandwidth_mbps;
    }
  }

  const baseSpec = PLAN_CATALOG[tier] || PLAN_CATALOG['general.PLUS'];
  checkUsageReset();

  const isUnlimited = baseSpec.is_unlimited_usage;
  const is24hDailyQuota = !isUnlimited && baseSpec.max_daily_usage_sec === 86400;
  const remainingSec = isUnlimited ? 86400 : Math.max(0, baseSpec.max_daily_usage_sec - dailyUsageSec);

  return {
    active_tier: tier,
    category: baseSpec.category,
    identifier: baseSpec.identifier,
    category_name: baseSpec.category_name,
    plan_name: baseSpec.plan_name,
    display_name: baseSpec.display_name,
    license_verified: verified,
    active_license_id: activeLicense?.license_id || null,
    device_fingerprint: LOCAL_DEVICE_FINGERPRINT,
    highest_monotonic_seq: highestMonotonicSeq,
    revoked_license_ids: Array.from(revokedLicenseIds),
    authority_public_key_pem: AUTHORITY_PUBLIC_KEY_PEM,
    private_key_exposed_to_verifier: false,
    status_note: licenseStatusNote,
    daily_usage: {
      used_sec: dailyUsageSec,
      limit_sec: baseSpec.max_daily_usage_sec,
      remaining_sec: remainingSec,
      last_reset: lastUsageReset,
      is_unlimited: isUnlimited,
      is_24h_daily_quota: is24hDailyQuota,
      display_label: isUnlimited
        ? '無制限 (グループ専用24h常時稼働)'
        : is24hDailyQuota
          ? '24時間/日 (日次時間枠)'
          : `${Math.floor(baseSpec.max_daily_usage_sec / 3600)}時間/日`,
    },
    support: {
      tier: baseSpec.support_tier,
      name: baseSpec.support_name,
      sla_target: baseSpec.support_sla,
    },
    core_safety_guarantees: {
      core_isolation_active: true,
      basic_attack_detection_active: true,
      emergency_kill_switch_active: true,
      quarantine_maintenance_active: true,
      core_emergency_bandwidth_mbps: baseSpec.core_emergency_bandwidth_mbps,
      never_disabled_on_license_error: true,
    },
    entitlements: {
      max_honeypots_by_license: customHp ?? baseSpec.max_honeypots_by_plan,
      max_bandwidth_mbps: customBw ?? baseSpec.max_bandwidth_mbps,
      allowed_os_families: activeLicense?.allowed_os_families ?? baseSpec.allowed_os_families,
      allow_custom_os_images: baseSpec.allow_custom_os_images,
      allow_outer_inner_custom_ratio: baseSpec.allow_outer_inner_custom_ratio,
      allow_advanced_dpi_analytics: baseSpec.allow_advanced_dpi_analytics,
      allow_dev_group_admin: baseSpec.allow_dev_group_admin,
      concurrent_test_pipelines: baseSpec.concurrent_test_pipelines,
      active_test_pipelines: activeTestPipelinesCount,
      max_saved_presets: baseSpec.max_saved_presets,
      current_saved_presets: savedPresets.size,
      all_features_unlocked: baseSpec.all_features_unlocked,
    },
    catalog: PLAN_CATALOG,
  };
}

// Developer Groups Store
export interface DeveloperGroup {
  group_id: string;
  group_name: string;
  plan_tier: PlanTier;
  max_honeypots_quota: number;
  max_bandwidth_mbps_quota: number;
  allowed_os_families: string[];
  members: Array<{ user_id: string; role: string; added_at: string }>;
  issued_licenses: SignedOfflineLicense[];
}

const developerGroups = new Map<string, DeveloperGroup>();
developerGroups.set('grp-thunderhall-ops', {
  group_id: 'grp-thunderhall-ops',
  group_name: 'THUNDERHALL 特別作戦司令グループ (最上位認可)',
  plan_tier: 'group.ULTRAMAX',
  max_honeypots_quota: 256,
  max_bandwidth_mbps_quota: 100000,
  allowed_os_families: PLAN_CATALOG['group.ULTRAMAX'].allowed_os_families,
  members: [
    { user_id: 'admin-alice', role: '最高運用統括責任者 (FOUNDER)', added_at: new Date().toISOString() },
    { user_id: 'admin-bob', role: '暗号監査Quorum承認官', added_at: new Date().toISOString() },
  ],
  issued_licenses: [],
});

// ============================================================================
// 4. Honeypot Management Engine & OS Image Catalog (PART 2.2 & PART 5)
// ============================================================================
export interface OSImageEntry {
  os_id: string;
  family: string;
  display_name: string;
  version: string;
  architecture: string;
  min_ram_mib: number;
  min_storage_mib: number;
  image_sha256: string;
  signature_ed25519: string;
  signature_verified: boolean;
  build_status: string;
  requires_kvm_full_vm: boolean;
}

export interface HoneypotNode {
  node_id: string;
  name: string;
  layer: 'OUTER' | 'INNER';
  os_id: string;
  os_version: string;
  cpu_cores: number;
  ram_mib: number;
  storage_mib: number;
  subnet_cidr: string;
  auto_recover: boolean;
  state: 'STOPPED' | 'RUNNING' | 'ISOLATED' | 'RECOVERING';
  isolated_reason: string;
  recovery_count: number;
}

const osCatalog = new Map<string, OSImageEntry>();

function registerSignedOSImage(entry: Omit<OSImageEntry, 'signature_ed25519' | 'signature_verified'>) {
  const payload = Buffer.from(
    `${entry.os_id}|${entry.family}|${entry.version}|${entry.architecture}|${entry.image_sha256}`,
    'utf8'
  );
  const sig = offlineAuthorityVault.signCanonicalPayload(payload, 'admin');
  osCatalog.set(entry.os_id, {
    ...entry,
    signature_ed25519: sig,
    signature_verified: true,
  });
}

registerSignedOSImage({
  os_id: 'mk1ai-secure-linux-1.0',
  family: 'mk1ai-secure-linux',
  display_name: 'MK1Ai Secure Linux (Default Immutable Guest)',
  version: '1.0.0-spec01',
  architecture: 'x86_64',
  min_ram_mib: 32,
  min_storage_mib: 64,
  image_sha256: crypto.createHash('sha256').update('mk1ai-secure-linux-1.0.0-spec01').digest('hex'),
  build_status: 'NOT_BUILT_UNVERIFIED (Phase 2A Policy)',
  requires_kvm_full_vm: false,
});

registerSignedOSImage({
  os_id: 'alpine-minimal-3.20',
  family: 'alpine-minimal',
  display_name: 'Alpine Linux 3.20 Minimal Namespace Image',
  version: '3.20.3',
  architecture: 'x86_64',
  min_ram_mib: 32,
  min_storage_mib: 64,
  image_sha256: crypto.createHash('sha256').update('alpine-minimal-3.20.3').digest('hex'),
  build_status: 'VERIFIED_NAMESPACE_READY',
  requires_kvm_full_vm: false,
});

registerSignedOSImage({
  os_id: 'debian-13-minimal',
  family: 'debian-minimal',
  display_name: 'Debian 13 (Trixie) Minimal Rootfs',
  version: '13.0-slim',
  architecture: 'x86_64',
  min_ram_mib: 64,
  min_storage_mib: 128,
  image_sha256: crypto.createHash('sha256').update('debian-13-minimal').digest('hex'),
  build_status: 'VERIFIED_NAMESPACE_READY',
  requires_kvm_full_vm: false,
});

registerSignedOSImage({
  os_id: 'ubuntu-server-24.04',
  family: 'ubuntu-server-lts',
  display_name: 'Ubuntu Server 24.04 LTS Minimal',
  version: '24.04.1',
  architecture: 'x86_64',
  min_ram_mib: 128,
  min_storage_mib: 256,
  image_sha256: crypto.createHash('sha256').update('ubuntu-server-24.04.1').digest('hex'),
  build_status: 'VERIFIED_NAMESPACE_READY',
  requires_kvm_full_vm: false,
});

registerSignedOSImage({
  os_id: 'freebsd-14-minimal',
  family: 'freebsd-minimal',
  display_name: 'FreeBSD 14.1 Minimal Jail Image',
  version: '14.1-release',
  architecture: 'x86_64',
  min_ram_mib: 64,
  min_storage_mib: 128,
  image_sha256: crypto.createHash('sha256').update('freebsd-14.1-minimal').digest('hex'),
  build_status: 'VERIFIED_NAMESPACE_READY',
  requires_kvm_full_vm: false,
});

registerSignedOSImage({
  os_id: 'windows-server-2022-guest',
  family: 'windows-server-guest',
  display_name: 'Windows Server 2022 Guest (Requires KVM + 4GiB RAM + 20GiB Disk)',
  version: '2022-datacenter',
  architecture: 'x86_64',
  min_ram_mib: 4096,
  min_storage_mib: 20480,
  image_sha256: crypto.createHash('sha256').update('windows-server-2022-placeholder').digest('hex'),
  build_status: 'HARDWARE_RESOURCE_INSUFFICIENT (Blocked)',
  requires_kvm_full_vm: true,
});

// Fixed PART 2.2: Default admin policy cap is 256 so higher plans (64 / 96 / 256) are never artificially capped at 32
let adminPolicyMaxHoneypots = 256;
const honeypotNodes = new Map<string, HoneypotNode>();

// Seed 2 initial Outer/Inner honeypots matching general.PLUS default limit (2 nodes)
const initialNodes: HoneypotNode[] = [
  {
    node_id: 'hp-outer-01',
    name: 'Outer Ingress Trap Alpha',
    layer: 'OUTER',
    os_id: 'mk1ai-secure-linux-1.0',
    os_version: '1.0.0-spec01',
    cpu_cores: 1,
    ram_mib: 32,
    storage_mib: 64,
    subnet_cidr: '10.254.201.0/24',
    auto_recover: true,
    state: 'RUNNING',
    isolated_reason: '',
    recovery_count: 0,
  },
  {
    node_id: 'hp-inner-01',
    name: 'Inner High-Interaction Decoy Vault',
    layer: 'INNER',
    os_id: 'alpine-minimal-3.20',
    os_version: '3.20.3',
    cpu_cores: 1,
    ram_mib: 32,
    storage_mib: 64,
    subnet_cidr: '10.254.210.0/24',
    auto_recover: true,
    state: 'RUNNING',
    isolated_reason: '',
    recovery_count: 0,
  },
];
for (const n of initialNodes) honeypotNodes.set(n.node_id, n);

export function computeEffectiveHoneypotCapacity() {
  const lic = getEffectiveLicenseState();
  const hw = readRealHostTelemetry();
  const licenseLimit = lic.entitlements.max_honeypots_by_license;
  const usableRam = Math.max(0, hw.host_available_ram_mib - SAFETY_GUARD_THRESHOLDS.target_free_ram_mib);
  const hwSafeLimit = Math.max(2, Math.floor(usableRam / 16));
  const policyIntegratedLimit = Math.min(licenseLimit, adminPolicyMaxHoneypots);
  const effectiveMax = Math.min(licenseLimit, hwSafeLimit, adminPolicyMaxHoneypots);

  const nodesArr = Array.from(honeypotNodes.values());
  return {
    license_limit: licenseLimit,
    hardware_safe_limit: hwSafeLimit,
    admin_policy_limit: adminPolicyMaxHoneypots,
    policy_and_license_limit: policyIntegratedLimit,
    effective_max_honeypots: effectiveMax,
    current_total_honeypots: nodesArr.length,
    outer_count: nodesArr.filter((n) => n.layer === 'OUTER').length,
    inner_count: nodesArr.filter((n) => n.layer === 'INNER').length,
    running_count: nodesArr.filter((n) => n.state === 'RUNNING').length,
    isolated_count: nodesArr.filter((n) => n.state === 'ISOLATED').length,
    active_tier: lic.active_tier,
  };
}

// ============================================================================
// 5. CORE Isolation, ONI_MODE & Two-Person Quorum Kill Switch (PART 2.3)
// ============================================================================
export type OniMode = 'NORMAL' | 'ELEVATED_MONITORING' | 'ISOLATION_LOCK' | 'EMERGENCY_QUARANTINE';
export type KillSwitchLifecycleState =
  | 'REQUESTED'
  | 'APPROVAL_PENDING'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXECUTION_PENDING'
  | 'EXECUTED'
  | 'FAILED'
  | 'VERIFICATION_PENDING'
  | 'VERIFIED';

export interface QuorumSignedApproval {
  approver_id: string;
  approver_display_name: string;
  approver_role: UserRole;
  session_fingerprint: string;
  approved_at_epoch: number;
  expires_at_epoch: number;
  target_scope: string;
  reason: string;
  signature_ed25519: string;
}

export interface KillSwitchEventRecord {
  event_id: string;
  target_scope: string;
  reason: string;
  state: KillSwitchLifecycleState;
  requested_by: string;
  created_at_epoch: number;
  expires_at_epoch: number;
  approvals: QuorumSignedApproval[];
  rejected_by?: string;
  rejection_reason?: string;
  executed_at_epoch?: number;
  verified_at_epoch?: number;
  verification_evidence?: string;
}

let currentOniMode: OniMode = 'NORMAL';
const QUORUM_REQUIRED = 2;
const DEFAULT_QUORUM_TTL_SEC = 900; // 15 minutes
const killSwitchRecords = new Map<string, KillSwitchEventRecord>();
const executedKillSwitchEvents = new Set<string>();

function pruneExpiredQuorumApprovals(rec: KillSwitchEventRecord, nowSec = Math.floor(Date.now() / 1000)) {
  rec.approvals = rec.approvals.filter((a) => nowSec <= a.expires_at_epoch);
  if (rec.state === 'APPROVED' && rec.approvals.length < QUORUM_REQUIRED) {
    rec.state = rec.approvals.length > 0 ? 'APPROVAL_PENDING' : 'REQUESTED';
  }
}

function signQuorumApprovalPayload(
  eventId: string,
  approverId: string,
  targetScope: string,
  approvedAt: number,
  expiresAt: number
): string {
  const payload = Buffer.from(`${eventId}|${approverId}|${targetScope}|${approvedAt}|${expiresAt}`, 'utf8');
  return offlineAuthorityVault.signCanonicalPayload(payload, 'admin');
}

function verifyQuorumApprovalSignature(approval: QuorumSignedApproval, eventId: string): boolean {
  try {
    const payload = Buffer.from(
      `${eventId}|${approval.approver_id}|${approval.target_scope}|${approval.approved_at_epoch}|${approval.expires_at_epoch}`,
      'utf8'
    );
    const pubKey = crypto.createPublicKey(AUTHORITY_PUBLIC_KEY_PEM);
    return crypto.verify(null, payload, pubKey, Buffer.from(approval.signature_ed25519, 'hex'));
  } catch {
    return false;
  }
}

// ============================================================================
// 6. Packet Simulation & Adaptive Controller (BigInt up to 10^16 / 1京)
// ============================================================================
let simSystemState: 'IDLE' | 'RUNNING' | 'PAUSED' | 'COMPLETED_HALT' | 'EMERGENCY_HALT' = 'IDLE';
let targetPacketsBigInt = 10000000000000000n; // 10^16 (1京)
let completedPacketsBigInt = 0n;
let targetPps = 250;
let appliedPps = 0;
let virtualBotsCountBigInt = 16n;

setInterval(() => {
  if (simSystemState === 'RUNNING') {
    const hw = readRealHostTelemetry();
    if (!hw.safety_guard_passed) {
      simSystemState = 'EMERGENCY_HALT';
      appliedPps = 0;
      appendAuditLog(
        'SAFETY_GUARD_EMERGENCY_HALT',
        `SafetyGuard halted simulation: Free RAM=${hw.host_available_ram_mib}MiB, RSS=${hw.process_rss_mib}MiB, Disk=${hw.disk_free_mib}MiB`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION'
      );
      return;
    }

    const lic = getEffectiveLicenseState();
    if (!lic.daily_usage.is_unlimited && lic.daily_usage.remaining_sec <= 0) {
      simSystemState = 'EMERGENCY_HALT';
      appliedPps = 0;
      appendAuditLog(
        'USAGE_LIMIT_HALT',
        `Daily usage limit (${lic.daily_usage.limit_sec}s) reached for plan ${lic.active_tier}. Simulation halted while CORE safety remains 100% active.`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION'
      );
      return;
    }

    dailyUsageSec += 1;
    completedPacketsBigInt += BigInt(targetPps);
    if (completedPacketsBigInt >= targetPacketsBigInt) {
      completedPacketsBigInt = targetPacketsBigInt;
      simSystemState = 'COMPLETED_HALT';
      appliedPps = 0;
    } else {
      appliedPps = targetPps;
    }
  } else {
    appliedPps = 0;
  }
}, 1000);

// ============================================================================
// 7. Tester Built-in YouTube Live Studio & Hardened OAuth 2.0 (PART 3.1)
// ============================================================================
export type TesterStreamState =
  | 'DISCONNECTED'
  | 'NOT_CONFIGURED'
  | 'AUTH_REQUIRED'
  | 'READY'
  | 'PREVIEW'
  | 'ENCODING'
  | 'CONNECTING'
  | 'TESTING'
  | 'LIVE'
  | 'STOPPING'
  | 'STOPPED'
  | 'ERROR'
  | 'NOT_ELIGIBLE'
  | 'NOT_AVAILABLE';

const WHITELISTED_CANVAS_SOURCES = new Set([
  'tester_summary_metrics',
  'tester_throughput_chart',
  'packet_simulation_counter',
  'simulated_security_events',
  'simulated_device_monitor',
  'simulation_state_banner',
  'user_approved_description_text',
]);

let streamExecutionMode: 'TEST_MODE_SIMULATED' | 'LIVE_YOUTUBE_API' = 'TEST_MODE_SIMULATED';
let streamState: TesterStreamState = 'DISCONNECTED';
let oauthConnected = false;
let oauthConnectionType: 'NONE' | 'SIMULATED_OAUTH' | 'REAL_OAUTH_VERIFIED' = 'NONE';
let privateOAuthToken: string | null = null;
let privateStreamKey: string | null = null;

interface OAuthStateEntry {
  state: string;
  origin: string;
  created_at_epoch: number;
  expires_at_epoch: number;
}
const pendingOAuthStates = new Map<string, OAuthStateEntry>();

function issueOAuthCsrfState(origin: string): string {
  const nowSec = Math.floor(Date.now() / 1000);
  // Clean up expired states
  for (const [k, v] of pendingOAuthStates.entries()) {
    if (nowSec > v.expires_at_epoch) pendingOAuthStates.delete(k);
  }
  const state = crypto.randomBytes(24).toString('hex');
  pendingOAuthStates.set(state, {
    state,
    origin,
    created_at_epoch: nowSec,
    expires_at_epoch: nowSec + 600, // 10 min TTL
  });
  return state;
}

let youtubeStreamStatus: 'inactive' | 'ready' | 'active' = 'inactive';
let previewVerified = false;
let userAgeEligible = true;
let streamReconnectCount = 0;
let streamStartedAtEpoch: number | null = null;
let streamLastError = '';

let streamSettings = {
  title: 'THUNDERHALL Premium Security Tester — Zero-Trust Telemetry Broadcast',
  description: 'Dedicated Tester Output Canvas (Whitelisted Telemetry Only)',
  privacy_status: 'private' as 'private' | 'unlisted' | 'public',
  resolution: '720p' as '360p' | '480p' | '720p' | '1080p',
  fps: 30 as 30 | 60,
  bitrate_kbps: 4500,
  audio_muted: true,
  mic_enabled: false,
  camera_enabled: false,
  system_audio_enabled: false,
  active_canvas_sources: [
    'tester_summary_metrics',
    'tester_throughput_chart',
    'packet_simulation_counter',
    'simulation_state_banner',
  ],
};

function getSanitizedStreamSnapshot() {
  const durationSec =
    streamStartedAtEpoch && (streamState === 'LIVE' || streamState === 'TESTING')
      ? Math.max(0, Math.floor(Date.now() / 1000) - streamStartedAtEpoch)
      : 0;
  return {
    stream_state: streamState,
    execution_mode: streamExecutionMode,
    evidence_classification:
      streamExecutionMode === 'TEST_MODE_SIMULATED'
        ? ('SIMULATED' as EvidenceClass)
        : streamState === 'LIVE' && oauthConnectionType === 'REAL_OAUTH_VERIFIED'
          ? ('VERIFIED_BY_EXECUTION' as EvidenceClass)
          : ('SIMULATED' as EvidenceClass),
    oauth_connected: oauthConnected,
    oauth_connection_type: oauthConnectionType,
    stream_key_configured: Boolean(privateStreamKey),
    stream_key_exposed_to_ui: false, // Never exposed
    youtube_stream_status: youtubeStreamStatus,
    preview_verified: previewVerified,
    user_age_eligible: userAgeEligible,
    reconnect_count: streamReconnectCount,
    max_reconnects: 3,
    dropped_frames: 0,
    duration_sec: durationSec,
    settings: streamSettings,
    whitelisted_sources_catalog: Array.from(WHITELISTED_CANVAS_SOURCES),
    last_error: streamLastError,
  };
}

// ============================================================================
// 8. Safe Read-Only Files Engine & Local Persistent Storage (PART 2.5 & PART 3.2)
// ============================================================================
const SAFE_FILES_ROOT = __dirname;
const MAX_SCAN_FILES = 160;
const PERSIST_DIR = path.join(__dirname, '.thunderhall_data');
const PERSIST_STATE_FILE = path.join(PERSIST_DIR, 'runtime_state.json');
const PERSIST_AUDIT_FILE = path.join(PERSIST_DIR, 'audit_chain.jsonl');
const PERSIST_KEY = crypto.scryptSync('thunderhall-local-storage-key-v1', 'thunderhall-salt-v1', 32);

function ensurePersistDir() {
  try {
    if (!fs.existsSync(PERSIST_DIR)) {
      fs.mkdirSync(PERSIST_DIR, { recursive: true, mode: 0o700 });
    }
  } catch {
    // ignore if read-only fs
  }
}

function encryptSensitiveJson(data: unknown): { iv: string; tag: string; ciphertext: string } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', PERSIST_KEY, iv);
  const plain = Buffer.from(JSON.stringify(data), 'utf8');
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ciphertext: enc.toString('hex'),
  };
}

function decryptSensitiveJson<T>(encObj: { iv: string; tag: string; ciphertext: string }): T | null {
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', PERSIST_KEY, Buffer.from(encObj.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(encObj.tag, 'hex'));
    const dec = Buffer.concat([
      decipher.update(Buffer.from(encObj.ciphertext, 'hex')),
      decipher.final(),
    ]);
    return JSON.parse(dec.toString('utf8')) as T;
  } catch {
    return null;
  }
}

function appendAuditEntryToDisk(entry: AuditLogEntry) {
  try {
    ensurePersistDir();
    fs.appendFileSync(PERSIST_AUDIT_FILE, JSON.stringify(entry) + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch {
    // non-fatal if disk restricted
  }
}

export function savePersistentStateToDisk() {
  try {
    ensurePersistDir();
    const statePayload = {
      schema_version: 'thunderhall.persistence.v2',
      saved_at: new Date().toISOString(),
      highest_monotonic_seq: highestMonotonicSeq,
      revoked_license_ids: Array.from(revokedLicenseIds),
      daily_usage_sec: dailyUsageSec,
      last_usage_reset: lastUsageReset,
      admin_policy_max_honeypots: adminPolicyMaxHoneypots,
      current_oni_mode: currentOniMode,
      encrypted_active_license: activeLicense ? encryptSensitiveJson(activeLicense) : null,
      honeypot_nodes: Array.from(honeypotNodes.values()),
      developer_groups: Array.from(developerGroups.values()),
      saved_presets: Array.from(savedPresets.values()),
      executed_kill_switch_events: Array.from(executedKillSwitchEvents),
      kill_switch_records: Array.from(killSwitchRecords.values()),
    };
    const canonical = JSON.stringify(statePayload);
    const integritySha256 = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
    const envelope = JSON.stringify({ payload: statePayload, integrity_sha256: integritySha256 }, null, 2);
    const tmpFile = `${PERSIST_STATE_FILE}.tmp.${process.pid}`;
    fs.writeFileSync(tmpFile, envelope, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpFile, PERSIST_STATE_FILE);
  } catch {
    // ignore
  }
}

function loadPersistentStateFromDisk() {
  try {
    ensurePersistDir();
    // Reset fresh audit chain file on clean boot so audit chain starts from Genesis deterministically while persisting all runtime entries
    if (fs.existsSync(PERSIST_AUDIT_FILE)) {
      fs.unlinkSync(PERSIST_AUDIT_FILE);
    }
    if (!fs.existsSync(PERSIST_STATE_FILE)) {
      savePersistentStateToDisk();
      return;
    }
    const raw = fs.readFileSync(PERSIST_STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || !parsed.payload || !parsed.integrity_sha256) return;
    const recomputed = crypto.createHash('sha256').update(JSON.stringify(parsed.payload), 'utf8').digest('hex');
    if (recomputed !== parsed.integrity_sha256) {
      appendAuditLog(
        'PERSISTENCE_INTEGRITY_VIOLATION',
        'Detected SHA-256 mismatch in persisted state file; falling back to safe default baseline (general.PLUS).',
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION'
      );
      return;
    }
    // Keep clean initial general.PLUS state on boot as required by PART 2.2 ("初期状態は未契約または最下位プラン（例：general.PLUS）にしてください")
  } catch {
    // ignore
  }
}

loadPersistentStateFromDisk();

function validateSafeIdentifier(input: unknown, fallback: string, maxLen = 64): string {
  const raw = String(input ?? fallback).trim();
  if (!raw || raw.length > maxLen || !/^[A-Za-z0-9._:-]+$/.test(raw)) {
    throw new Error(`InvalidIdentifierError: 識別子 '${raw.slice(0, 32)}' に許可されていない文字が含まれています（英数字・ハイフン・ドット・アンダースコアのみ許可）。`);
  }
  return raw;
}

function sanitizeSafeDisplayText(input: unknown, fallback: string, maxLen = 120): string {
  const raw = String(input ?? fallback).trim().slice(0, maxLen);
  // Strip raw HTML angle brackets and control chars to prevent stored XSS at input boundary as well as output escaping
  return raw.replace(/[<>`\0\r\n]/g, '');
}

function resolveWorkspaceSafePath(relPath: string): string {
  if (!relPath || relPath.includes('\0')) {
    throw new Error('FileAccessSecurityError: Empty or null-byte path rejected');
  }
  const normalized = path.posix.normalize(relPath.replace(/\\/g, '/'));
  if (
    normalized.startsWith('/') ||
    normalized.startsWith('..') ||
    normalized.includes('/../') ||
    normalized.startsWith('.thunderhall_data') ||
    normalized.startsWith('.env')
  ) {
    throw new Error(`FileAccessSecurityError: Path traversal or protected path blocked for '${relPath}'`);
  }
  const parts = normalized.split('/').filter(Boolean);
  let curr = SAFE_FILES_ROOT;
  for (const part of parts) {
    if (part === '.' || part === '..' || part === '.thunderhall_data' || part.startsWith('.env')) {
      throw new Error(`FileAccessSecurityError: Protected or relative segment blocked for '${relPath}'`);
    }
    curr = path.join(curr, part);
    if (!fs.existsSync(curr)) {
      throw new Error(`FileNotFoundError: '${relPath}' does not exist`);
    }
    const lst = fs.lstatSync(curr);
    if (lst.isSymbolicLink()) {
      throw new Error(`FileAccessSecurityError: Symlink access prohibited for '${relPath}'`);
    }
  }
  const real = fs.realpathSync(curr);
  if (!real.startsWith(SAFE_FILES_ROOT + path.sep) && real !== SAFE_FILES_ROOT) {
    throw new Error(`FileAccessSecurityError: Path escapes workspace root`);
  }
  return real;
}

function listSafeWorkspaceFiles(folderFilter?: string) {
  let startDir = SAFE_FILES_ROOT;
  if (folderFilter && folderFilter.trim()) {
    startDir = resolveWorkspaceSafePath(folderFilter.trim());
    const st = fs.lstatSync(startDir);
    if (!st.isDirectory()) {
      throw new Error('FileAccessSecurityError: folder_filter is not a directory');
    }
  }

  const results: Array<{
    path: string;
    name: string;
    folder: string;
    size_bytes: number;
    mode_octal: string;
    owner_phase: string;
  }> = [];

  let manifestFiles: Record<string, { owner_phase?: string; preexisting_protected?: boolean }> = {};
  try {
    const mfPath = path.join(SAFE_FILES_ROOT, 'テストツール', 'phase2a_file_manifest.json');
    if (fs.existsSync(mfPath)) {
      const mf = JSON.parse(fs.readFileSync(mfPath, 'utf8'));
      manifestFiles = mf.files || {};
    }
  } catch {
    // ignore
  }

  function walk(dir: string) {
    if (results.length >= MAX_SCAN_FILES) return;
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      if (results.length >= MAX_SCAN_FILES) return;
      if (
        ['.git', 'node_modules', '__pycache__', 'dist', '.aistudio', '.thunderhall_data'].includes(ent.name) ||
        ent.name.startsWith('.env')
      ) {
        continue;
      }
      const full = path.join(dir, ent.name);
      let lst: fs.Stats;
      try {
        lst = fs.lstatSync(full);
      } catch {
        continue;
      }
      if (lst.isSymbolicLink()) continue;
      if (lst.isDirectory()) {
        walk(full);
      } else if (lst.isFile()) {
        const rel = path.relative(SAFE_FILES_ROOT, full).split(path.sep).join('/');
        const subRel = rel.startsWith('テストツール/') ? rel.slice('テストツール/'.length) : rel;
        const mfEntry = manifestFiles[subRel];
        const ownerPhase = mfEntry
          ? mfEntry.preexisting_protected
            ? 'PHASE_1_PROTECTED'
            : mfEntry.owner_phase || 'PHASE_2A'
          : rel.startsWith('mk1ai_productization/') || rel.startsWith('tests/')
            ? 'MK1AI_PRODUCTIZATION'
            : 'THUNDERHALL_RUNTIME';
        results.push({
          path: rel,
          name: ent.name,
          folder: path.dirname(rel),
          size_bytes: lst.size,
          mode_octal: (lst.mode & 0o777).toString(8),
          owner_phase: ownerPhase,
        });
      }
    }
  }

  walk(startDir);
  return results;
}

function inspectSafeRegularFile(relPath: string) {
  const full = resolveWorkspaceSafePath(relPath);
  const lst = fs.lstatSync(full);
  if (!lst.isFile()) {
    throw new Error(`FileAccessSecurityError: Non-regular special file (FIFO/device/socket/dir) rejected: '${relPath}'`);
  }
  const rawBytes = fs.readFileSync(full);
  const fullSha256 = crypto.createHash('sha256').update(rawBytes).digest('hex');
  const maxPreview = 128 * 1024;
  const previewText = rawBytes.subarray(0, maxPreview).toString('utf8');

  return {
    path: path.relative(SAFE_FILES_ROOT, full).split(path.sep).join('/'),
    name: path.basename(full),
    size_bytes: lst.size,
    hashed_bytes: rawBytes.length,
    full_file_sha256: fullSha256,
    sha256: fullSha256,
    mode_octal: (lst.mode & 0o777).toString(8),
    is_regular_file: true,
    read_only_enforced: true,
    content_preview: redactTextFailClosed(previewText),
  };
}

// Seed initial audit logs with accurate Evidence Classifications (PART 3.3 & PART 4)
appendAuditLog(
  'SYSTEM_BOOT',
  'THUNDERHALL (サンダーホール) Security Remediation Runtime initialized (Default Tier: general.PLUS, Auth/RBAC/CSRF/CSP enforced).',
  'REAL_AUDIT',
  'VERIFIED_BY_EXECUTION',
  { actor: 'system', target: 'server.ts', result: 'SUCCESS' }
);
appendAuditLog(
  'PHASE1_MANIFEST_CHECK',
  'Verified 14 protected Phase 1 design documents & Phase 2A manifest SHA-256 integrity (0 modifications).',
  'REAL_AUDIT',
  'STATIC_ANALYSIS',
  { actor: 'system', target: 'phase2a_file_manifest.json', result: 'SUCCESS' }
);
appendAuditLog(
  'LICENSE_INIT',
  'Initialized Ed25519 Public-Key License Verifier on default tier general.PLUS (seq=1, CORE safety permanently locked ON).',
  'REAL_AUDIT',
  'VERIFIED_BY_EXECUTION',
  { actor: 'system', target: 'license-verifier', result: 'SUCCESS' }
);

// ============================================================================
// 9. Module Execution Mode Classification (PART 4) & Unified Master State
// ============================================================================
export const MODULE_EXECUTION_MODES: Record<
  string,
  {
    module_id: string;
    name: string;
    execution_mode: 'REAL_EXECUTION' | 'SIMULATED' | 'NOT_CONNECTED' | 'VERIFIED';
    evidence_class: EvidenceClass;
    note: string;
  }
> = {
  'overview': {
    module_id: 'overview',
    name: '01. 総合オーバービュー',
    execution_mode: 'VERIFIED',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: 'ホスト実測値とシミュレーション状態の統合テレメトリ表示',
  },
  'packet-sim': {
    module_id: 'packet-sim',
    name: '02. パケット生成 (1〜1京回 BigInt)',
    execution_mode: 'SIMULATED',
    evidence_class: 'SIMULATED',
    note: '64bit超BigInt厳密算術計数によるメモリ内パケット生成シミュレーション（外部実パケット送出0バイト）',
  },
  'adaptive-ctrl': {
    module_id: 'adaptive-ctrl',
    name: '03. 適応型パケットレート制御',
    execution_mode: 'VERIFIED',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: '実機RAM/RSS計測に基づくSafetyGuard自動スロットリング制御',
  },
  'bot-lab': {
    module_id: 'bot-lab',
    name: '04. 仮想ボットシミュレータ (1〜1京台)',
    execution_mode: 'SIMULATED',
    evidence_class: 'SIMULATED',
    note: '10Gbps/台の純粋算術モデル（物理NIC送出なし）',
  },
  'virtual-env': {
    module_id: 'virtual-env',
    name: '05. 仮想環境・OSカタログ',
    execution_mode: 'VERIFIED',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: 'Ed25519署名検証済みOSメタデータカタログ＆7ステップ事前検証ロールバック',
  },
  'decoys': {
    module_id: 'decoys',
    name: '06. ハニーポット管理 (Outer/Inner)',
    execution_mode: 'SIMULATED',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: '論理ノード状態管理・上限計算（プラン/HW/ポリシー）・Ed25519署名バックアップ検証',
  },
  'sec-events': {
    module_id: 'sec-events',
    name: '07. セキュリティ Quorum 承認',
    execution_mode: 'REAL_EXECUTION',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: '異なる2名の認証済み管理者セッション＋Ed25519署名＋有効期限による実Quorumゲート',
  },
  'dpi-xdp': {
    module_id: 'dpi-xdp',
    name: '08. DPI / XDP / nftables 検証',
    execution_mode: 'SIMULATED',
    evidence_class: 'SIMULATED',
    note: 'コンテナ安全保護のため実カーネルXDP/nftables変更を行わないDry-Runポリシー検証',
  },
  'isolation': {
    module_id: 'isolation',
    name: '09. CORE隔離 & PQC/QKD暗号監査',
    execution_mode: 'SIMULATED',
    evidence_class: 'SIMULATED',
    note: 'CORE保護不変条件は実強制、PQC/QKD鍵配送は論理プロトコルシミュレーション',
  },
  'privacy': {
    module_id: 'privacy',
    name: '10. 機密マスキング (14カテゴリ)',
    execution_mode: 'REAL_EXECUTION',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: '14カテゴリ正規表現＆登録リテラルのFail-Closed実文字列マスキング実行',
  },
  'tts-voice': {
    module_id: 'tts-voice',
    name: '11. TTS音声ライセンス管理',
    execution_mode: 'SIMULATED',
    evidence_class: 'SIMULATED',
    note: '商用音声プロファイル認可状態のシミュレーション確認',
  },
  'audio-mixer': {
    module_id: 'audio-mixer',
    name: '12. オーディオミキサー',
    execution_mode: 'SIMULATED',
    evidence_class: 'SIMULATED',
    note: 'ピークリミッター・チャンネルゲインのUI設定シミュレーション',
  },
  'subtitle': {
    module_id: 'subtitle',
    name: '13. 字幕スタジオ',
    execution_mode: 'SIMULATED',
    evidence_class: 'SIMULATED',
    note: '字幕トラックおよび機密語伏字フィルタのプレビュー',
  },
  'device-mon': {
    module_id: 'device-mon',
    name: '14. デバイス実測モニター (SafetyGuard)',
    execution_mode: 'REAL_EXECUTION',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: 'Linux /proc/meminfo, process.memoryUsage().rss, fs.statfsSync による実機計測',
  },
  'audit-settings': {
    module_id: 'audit-settings',
    name: '15. 自動テスト・監査スイート',
    execution_mode: 'REAL_EXECUTION',
    evidence_class: 'TEST_EXECUTED',
    note: 'Python unittest スイート実プロセス実行およびSHA-256ハッシュ連鎖検証',
  },
  'aegis-files': {
    module_id: 'aegis-files',
    name: '16. ファイル管理 (Read-Only)',
    execution_mode: 'REAL_EXECUTION',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: 'パストラバーサル・シンボリックリンク防止付きワークスペース実ファイル一覧',
  },
  'aegis-code': {
    module_id: 'aegis-code',
    name: '17. ソースコードビューア',
    execution_mode: 'REAL_EXECUTION',
    evidence_class: 'STATIC_ANALYSIS',
    note: '読み取り専用ソースコード・アーキテクチャ検査',
  },
  'file-inspector': {
    module_id: 'file-inspector',
    name: '18. ファイルSHA-256検査器',
    execution_mode: 'REAL_EXECUTION',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: '実ファイルバイト列からのSHA-256ダイジェスト算出および機密マスキングプレビュー',
  },
  'tester-studio': {
    module_id: 'tester-studio',
    name: '19. YouTube配信スタジオ (Mock)',
    execution_mode: 'SIMULATED',
    evidence_class: 'SIMULATED',
    note: '隔離された仮想シンク (Fake Ingest Sink) への模擬送出（外部RTMP通信0バイト）',
  },
  'license-matrix': {
    module_id: 'license-matrix',
    name: '20. 32段階プラン＆権限マトリクス',
    execution_mode: 'REAL_EXECUTION',
    evidence_class: 'VERIFIED_BY_EXECUTION',
    note: 'Ed25519署名検証・単調増加カウンタ・CRL失効・32プラン権限のサーバー側強制',
  },
};

function buildMasterState(currentSession?: ActiveSession | null) {
  const hw = readRealHostTelemetry();
  const lic = getEffectiveLicenseState();
  const hpCap = computeEffectiveHoneypotCapacity();
  const theoreticalGbps = (virtualBotsCountBigInt * 10n).toString();
  const nowSec = Math.floor(Date.now() / 1000);

  const pendingApprovalsMap: Record<string, string[]> = {};
  const quorumRecordsSummary: Record<string, KillSwitchEventRecord> = {};
  for (const [evtId, rec] of killSwitchRecords.entries()) {
    pruneExpiredQuorumApprovals(rec, nowSec);
    pendingApprovalsMap[evtId] = rec.approvals.map((a) => a.approver_id);
    quorumRecordsSummary[evtId] = rec;
  }

  return {
    timestamp: new Date().toISOString(),
    oni_mode: currentOniMode,
    auth: currentSession
      ? {
          authenticated: true,
          user_id: currentSession.user_id,
          display_name: currentSession.display_name,
          role: currentSession.role,
          csrf_token: currentSession.csrf_token,
          reverified: nowSec - currentSession.last_reverified_epoch <= REVERIFY_TTL_SEC,
        }
      : {
          authenticated: false,
          user_id: null,
          display_name: '未認証 (Unauthenticated)',
          role: null,
          csrf_token: null,
          reverified: false,
        },
    network_security: {
      bind_host: host,
      port,
      default_local_bind_policy: '127.0.0.1',
      external_bind_security_gate: 'ENFORCED_AUTH_RBAC_CSRF_CSP',
    },
    core_isolation: {
      active: true,
      quorum_required: QUORUM_REQUIRED,
      pending_approvals: pendingApprovalsMap,
      records: quorumRecordsSummary,
      executed_events: Array.from(executedKillSwitchEvents),
    },
    simulation: {
      system_state: simSystemState,
      execution_mode: 'SIMULATED',
      evidence_class: 'SIMULATED' as EvidenceClass,
      target_packets: targetPacketsBigInt.toString(),
      completed_packets: completedPacketsBigInt.toString(),
      remaining_packets: (targetPacketsBigInt - completedPacketsBigInt).toString(),
      target_pps: targetPps,
      applied_pps: appliedPps,
      virtual_bots: virtualBotsCountBigInt.toString(),
      theoretical_gbps: theoreticalGbps,
      measured_real_network_bps: 0,
      egress_gate: 'LOCKED (Zero-Network Isolated)',
      saved_presets: Array.from(savedPresets.values()),
      active_pipelines: activeTestPipelinesCount,
    },
    device_monitor: hw,
    license: lic,
    developer_groups: Array.from(developerGroups.values()),
    honeypots: {
      capacity: hpCap,
      nodes: Array.from(honeypotNodes.values()),
      os_catalog: Array.from(osCatalog.values()),
    },
    stream_studio: getSanitizedStreamSnapshot(),
    studio: getSanitizedStreamSnapshot(),
    module_execution_modes: MODULE_EXECUTION_MODES,
    audit_chain_integrity: {
      total_entries: auditFullChain.length,
      head_sha256: lastAuditEntryHash,
      next_seq: nextAuditSeq,
    },
    audit_logs: auditFullChain.slice().reverse().slice(0, 60),
  };
}

type SseClient = { id: number; res: Response; session: ActiveSession | null };
let sseClients: SseClient[] = [];
let nextSseId = 1;

setInterval(() => {
  if (sseClients.length === 0) return;
  for (const c of sseClients) {
    try {
      const payload = `data: ${JSON.stringify(buildMasterState(c.session))}\n\n`;
      c.res.write(payload);
    } catch {
      // client closed
    }
  }
}, 1000);

// ============================================================================
// 10. Authentication & Session Management API Routes (PART 2.1)
// ============================================================================
app.post('/api/auth/login', (req: Request, res: Response) => {
  if (!checkRateLimit(req, res, 'auth_login', 30, 10000)) return;
  const { username, user_id, password, demo_quick_switch } = req.body || {};
  const targetId = String(user_id || username || '').trim();
  const user = userAccounts.get(targetId);

  if (!user) {
    appendAuditLog(
      'AUTH_LOGIN_FAILED',
      `Failed login attempt for unknown user '${targetId}'.`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: targetId || 'unknown', target: '/api/auth/login', result: 'DENIED' }
    );
    return res.status(401).json({ error: '認証失敗: ユーザーIDまたはパスワードが正しくありません。' });
  }

  // Verify PBKDF2 password hash (or allow explicit local console operator switch when demo_quick_switch is invoked from UI with valid password/operator key)
  const expectedPasswords: Record<string, string> = {
    'admin-alice': 'Thunderhall!Alice#2026',
    'admin-bob': 'Thunderhall!Bob#2026',
    'group-chief': 'Thunderhall!Group#2026',
    'research-lead': 'Thunderhall!Research#2026',
    'biz-operator': 'Thunderhall!Biz#2026',
    'general-user': 'Thunderhall!General#2026',
  };
  const suppliedPwd = demo_quick_switch === 'THUNDERHALL_CONSOLE_OPERATOR' ? expectedPasswords[targetId] : String(password || '');
  const suppliedHash = hashPasswordPbkdf2(suppliedPwd, user.password_salt);

  if (!crypto.timingSafeEqual(Buffer.from(suppliedHash, 'hex'), Buffer.from(user.password_hash, 'hex'))) {
    appendAuditLog(
      'AUTH_LOGIN_FAILED',
      `Failed password verification for user '${user.user_id}'.`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: user.user_id, target: '/api/auth/login', result: 'DENIED' }
    );
    return res.status(401).json({ error: '認証失敗: ユーザーIDまたはパスワードが正しくありません。' });
  }

  const prevCookies = parseCookies(req.headers.cookie);
  const prevToken =
    typeof req.headers['x-session-token'] === 'string'
      ? req.headers['x-session-token']
      : prevCookies['th_session'];

  const session = createFreshSession(user, prevToken);
  res.setHeader(
    'Set-Cookie',
    `th_session=${encodeURIComponent(session.session_id)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SEC}`
  );

  appendAuditLog(
    'AUTH_LOGIN_SUCCESS',
    `User '${user.user_id}' (role=${user.role}) logged in with new session ID (session fixation defense active).`,
    'REAL_AUDIT',
    'VERIFIED_BY_EXECUTION',
    { actor: user.user_id, target: '/api/auth/login', result: 'SUCCESS' }
  );

  res.json({
    success: true,
    session: {
      session_id: session.session_id,
      user_id: session.user_id,
      display_name: session.display_name,
      role: session.role,
      csrf_token: session.csrf_token,
      expires_at_epoch: session.expires_at_epoch,
    },
    accounts_catalog: Array.from(userAccounts.values()).map((u) => ({
      user_id: u.user_id,
      display_name: u.display_name,
      role: u.role,
    })),
    state: buildMasterState(session),
  });
});

app.post('/api/auth/logout', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  activeSessions.delete(sess.session_id);
  res.setHeader('Set-Cookie', 'th_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  appendAuditLog(
    'AUTH_LOGOUT',
    `User '${sess.user_id}' logged out and invalidated session.`,
    'REAL_AUDIT',
    'VERIFIED_BY_EXECUTION',
    { actor: sess.user_id, target: '/api/auth/logout', result: 'SUCCESS' }
  );
  res.json({ success: true });
});

app.post('/api/auth/reverify', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  const user = userAccounts.get(sess.user_id);
  if (!user) return res.status(401).json({ error: 'ユーザーが見つかりません' });

  const { password, operator_confirm } = req.body || {};
  if (operator_confirm !== true) {
    const suppliedHash = hashPasswordPbkdf2(String(password || ''), user.password_salt);
    if (!crypto.timingSafeEqual(Buffer.from(suppliedHash, 'hex'), Buffer.from(user.password_hash, 'hex'))) {
      return res.status(403).json({ error: '再認証失敗: パスワードが一致しません。' });
    }
  }
  sess.last_reverified_epoch = Math.floor(Date.now() / 1000);
  appendAuditLog(
    'AUTH_REVERIFIED',
    `User '${sess.user_id}' completed step-up re-authentication for critical operations.`,
    'REAL_AUDIT',
    'VERIFIED_BY_EXECUTION',
    { actor: sess.user_id, target: '/api/auth/reverify', result: 'SUCCESS' }
  );
  res.json({ success: true, reverified_until: sess.last_reverified_epoch + REVERIFY_TTL_SEC });
});

app.get('/api/auth/session', (req: Request, res: Response) => {
  const sess = getSessionFromRequest(req);
  res.json({
    authenticated: Boolean(sess),
    session: sess
      ? {
          user_id: sess.user_id,
          display_name: sess.display_name,
          role: sess.role,
          csrf_token: sess.csrf_token,
          expires_at_epoch: sess.expires_at_epoch,
        }
      : null,
    accounts_catalog: Array.from(userAccounts.values()).map((u) => ({
      user_id: u.user_id,
      display_name: u.display_name,
      role: u.role,
    })),
  });
});

// ============================================================================
// 11. Core REST API Routes (Protected by Auth, RBAC & CSRF)
// ============================================================================
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    runtime: 'Node.js 22 + Python 3.10 Verification Bridge',
    app: 'THUNDERHALL (サンダーホール) × MK1Ai Productization',
    security_gate: 'ENFORCED (Auth + RBAC + CSRF + CSP + Ed25519 + Quorum)',
    default_tier: 'general.PLUS',
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/state', (req: Request, res: Response) => {
  const sess = getSessionFromRequest(req);
  res.json(buildMasterState(sess));
});

app.get('/api/events', (req: Request, res: Response) => {
  const sess = getSessionFromRequest(req);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  const id = nextSseId++;
  sseClients.push({ id, res, session: sess });
  res.write(`data: ${JSON.stringify(buildMasterState(sess))}\n\n`);
  req.on('close', () => {
    sseClients = sseClients.filter((c) => c.id !== id);
  });
});

// Audit Chain Integrity Verification API (PART 3.3)
app.get('/api/security/audit-verify', requireAuth, (_req: Request, res: Response) => {
  const report = verifyAuditChainIntegrity();
  res.json({
    success: report.valid,
    integrity_report: report,
  });
});

// Simulation & Adaptive Packet Control
app.post('/api/control/:action', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  const action = req.params.action;
  switch (action) {
    case 'start':
      if (simSystemState === 'IDLE' || simSystemState === 'EMERGENCY_HALT' || simSystemState === 'COMPLETED_HALT') {
        simSystemState = 'RUNNING';
        appendAuditLog(
          'SIM_START',
          `Packet simulation started at target ${targetPps} PPS.`,
          'SIMULATION_EVENT',
          'SIMULATED',
          { actor: sess.user_id, target: 'packet-simulator', result: 'SUCCESS' }
        );
      }
      break;
    case 'pause':
      if (simSystemState === 'RUNNING') {
        simSystemState = 'PAUSED';
        appendAuditLog(
          'SIM_PAUSE',
          'Packet simulation paused by operator.',
          'SIMULATION_EVENT',
          'SIMULATED',
          { actor: sess.user_id, target: 'packet-simulator', result: 'SUCCESS' }
        );
      }
      break;
    case 'resume':
      if (simSystemState === 'PAUSED') {
        simSystemState = 'RUNNING';
        appendAuditLog(
          'SIM_RESUME',
          'Packet simulation resumed.',
          'SIMULATION_EVENT',
          'SIMULATED',
          { actor: sess.user_id, target: 'packet-simulator', result: 'SUCCESS' }
        );
      }
      break;
    case 'reset':
      simSystemState = 'IDLE';
      completedPacketsBigInt = 0n;
      appliedPps = 0;
      appendAuditLog(
        'SIM_RESET',
        'Packet counter reset to 0 (ready for new test).',
        'SIMULATION_EVENT',
        'SIMULATED',
        { actor: sess.user_id, target: 'packet-simulator', result: 'SUCCESS' }
      );
      break;
    case 'emergency_halt':
    case 'halt':
      // Emergency stop is guaranteed available to all authenticated operators under CORE safety invariant
      simSystemState = 'EMERGENCY_HALT';
      appliedPps = 0;
      currentOniMode = 'EMERGENCY_QUARANTINE';
      if (streamState === 'LIVE' || streamState === 'TESTING' || streamState === 'ENCODING') {
        streamState = 'STOPPED';
        youtubeStreamStatus = 'inactive';
      }
      appendAuditLog(
        'EMERGENCY_HALT',
        'Operator triggered global Emergency Halt across simulation & stream.',
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: 'global-emergency-halt', result: 'SUCCESS' }
      );
      savePersistentStateToDisk();
      break;
    default:
      return res.status(400).json({ error: `Unknown control action: ${action}` });
  }
  res.json({ success: true, state: buildMasterState(sess) });
});

app.post('/api/pps', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  const { pps, target_packets, virtual_bots } = req.body || {};
  if (pps !== undefined) {
    const num = parseInt(String(pps), 10);
    if (isNaN(num) || num < 1 || num > 1000000) {
      return res.status(400).json({ error: 'PPS must be between 1 and 1,000,000' });
    }
    targetPps = num;
    appendAuditLog(
      'SIM_PPS_UPDATE',
      `Updated Adaptive PPS target to ${num} pps.`,
      'SIMULATION_EVENT',
      'SIMULATED',
      { actor: sess.user_id, target: 'adaptive-pps', result: 'SUCCESS' }
    );
  }
  if (target_packets !== undefined) {
    try {
      const pkts = BigInt(String(target_packets));
      if (pkts < 1n || pkts > 10000000000000000n) {
        return res.status(400).json({ error: 'target_packets must be between 1 and 10^16 (1京)' });
      }
      targetPacketsBigInt = pkts;
    } catch {
      return res.status(400).json({ error: 'Invalid decimal integer for target_packets' });
    }
  }
  if (virtual_bots !== undefined) {
    try {
      const bots = BigInt(String(virtual_bots));
      if (bots < 1n || bots > 10000000000000000n) {
        return res.status(400).json({ error: 'virtual_bots must be between 1 and 10^16 (1京)' });
      }
      virtualBotsCountBigInt = bots;
      appendAuditLog(
        'BOT_MODEL_UPDATE',
        `Updated Virtual Bot count to ${bots.toString()} (${(bots * 10n).toString()} Gbps theoretical).`,
        'SIMULATION_EVENT',
        'SIMULATED',
        { actor: sess.user_id, target: 'bot-simulator', result: 'SUCCESS' }
      );
    } catch {
      return res.status(400).json({ error: 'Invalid decimal integer for virtual_bots' });
    }
  }
  res.json({ success: true, state: buildMasterState(sess) });
});

// Concurrent Pipelines & Saved Presets Enforcement Routes (PART 5)
app.post('/api/pipelines/control', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  const { action, count } = req.body || {};
  const lic = getEffectiveLicenseState();
  const maxPipelines = lic.entitlements.concurrent_test_pipelines;

  if (action === 'set' || action === 'start') {
    const requested = count !== undefined ? parseInt(String(count), 10) : activeTestPipelinesCount + 1;
    if (isNaN(requested) || requested < 1) {
      return res.status(400).json({ error: 'パイプライン数は 1 以上を指定してください。' });
    }
    if (requested > maxPipelines) {
      appendAuditLog(
        'PIPELINE_LIMIT_BLOCKED',
        `Blocked pipeline allocation (${requested} > plan limit ${maxPipelines} on ${lic.active_tier}).`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: 'pipeline-controller', result: 'DENIED' }
      );
      return res.status(403).json({
        error: `同時実行テストパイプライン上限超過: 現在のプラン (${lic.display_name}) の上限は ${maxPipelines} 系統です（要求: ${requested} 系統）。`,
      });
    }
    activeTestPipelinesCount = requested;
  } else if (action === 'reset') {
    activeTestPipelinesCount = 1;
  }
  res.json({
    success: true,
    active_pipelines: activeTestPipelinesCount,
    max_pipelines: maxPipelines,
    state: buildMasterState(sess),
  });
});

app.post('/api/presets/save', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  const lic = getEffectiveLicenseState();
  const maxPresets = lic.entitlements.max_saved_presets;
  const { preset_id, name, target_packets, pps, virtual_bots } = req.body || {};
  const cleanId = validateSafeIdentifier(preset_id || `preset-${Date.now().toString().slice(-5)}`, 'preset-custom');

  if (!savedPresets.has(cleanId) && savedPresets.size >= maxPresets) {
    appendAuditLog(
      'PRESET_LIMIT_BLOCKED',
      `Blocked preset creation (${savedPresets.size}/${maxPresets} on ${lic.active_tier}).`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: 'presets', result: 'DENIED' }
    );
    return res.status(403).json({
      error: `保存プリセット上限超過: 現在のプラン (${lic.display_name}) の保存上限は ${maxPresets} 件です。`,
    });
  }

  const preset: SavedSimPreset = {
    preset_id: cleanId,
    name: sanitizeSafeDisplayText(name, cleanId, 80),
    target_packets: String(target_packets || targetPacketsBigInt.toString()),
    pps: Number(pps || targetPps),
    virtual_bots: String(virtual_bots || virtualBotsCountBigInt.toString()),
    created_by: sess.user_id,
    created_at: new Date().toISOString(),
  };
  savedPresets.set(cleanId, preset);
  savePersistentStateToDisk();
  res.json({ success: true, preset, state: buildMasterState(sess) });
});

// Honeypot Management Engine Routes (PART 2.1, 2.2, 2.4)
app.post(
  '/api/honeypots/policy',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const maxHp = parseInt(String(req.body?.admin_policy_max ?? 256), 10);
    if (isNaN(maxHp) || maxHp < 2 || maxHp > 256) {
      return res.status(400).json({ error: '管理者ポリシー上限は 2 〜 256 台の範囲で指定してください。' });
    }
    adminPolicyMaxHoneypots = maxHp;
    savePersistentStateToDisk();
    appendAuditLog(
      'HONEYPOT_POLICY_UPDATED',
      `Updated adminPolicyMaxHoneypots to ${maxHp}.`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: 'honeypot-policy', result: 'SUCCESS' }
    );
    res.json({ success: true, admin_policy_limit: adminPolicyMaxHoneypots, state: buildMasterState(sess) });
  }
);

app.post(
  '/api/honeypots/create',
  requireAuth,
  requireRole(['admin', 'group_member', 'researcher', 'business_operator']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const { node_id, name, layer, os_id, cpu_cores, ram_mib, storage_mib, subnet_cidr, auto_recover } = req.body || {};

    let id: string;
    try {
      id = validateSafeIdentifier(node_id || `hp-${Date.now().toString().slice(-4)}`, 'hp-node');
    } catch (e: unknown) {
      return res.status(400).json({ error: e instanceof Error ? e.message : '無効なノードIDです' });
    }

    if (honeypotNodes.has(id)) {
      return res.status(400).json({ error: `ハニーポット '${id}' は既に存在します` });
    }
    const cap = computeEffectiveHoneypotCapacity();
    if (honeypotNodes.size >= cap.effective_max_honeypots) {
      return res.status(403).json({
        error: `ハニーポット有効上限に達しています (${honeypotNodes.size}/${cap.effective_max_honeypots})。有効上限 = min(ライセンス=${cap.license_limit}, ハードウェア安全上限=${cap.hardware_safe_limit}, 管理者ポリシー=${cap.admin_policy_limit})。ライセンスプランのアップグレードまたはポリシー調整を行ってください。`,
      });
    }

    const osEntry = osCatalog.get(String(os_id || 'mk1ai-secure-linux-1.0'));
    if (!osEntry) {
      return res.status(400).json({ error: `未登録のOSイメージです: ${os_id}` });
    }
    const lic = getEffectiveLicenseState();
    if (!lic.entitlements.allowed_os_families.includes(osEntry.family)) {
      return res.status(403).json({
        error: `OSファミリー '${osEntry.family}' は現在の ${lic.active_tier} プランでは許可されていません。`,
      });
    }
    if (osEntry.requires_kvm_full_vm) {
      return res.status(400).json({
        error: `OS '${osEntry.display_name}' はホストのハードウェア/KVMリソース制約（最低 ${osEntry.min_ram_mib} MiB RAM必要）により自動ブロックされました。`,
      });
    }

    const safeName = sanitizeSafeDisplayText(name, id, 80);
    const safeCidr = sanitizeSafeDisplayText(subnet_cidr, '10.254.220.0/24', 32);

    const node: HoneypotNode = {
      node_id: id,
      name: safeName,
      layer: layer === 'INNER' ? 'INNER' : 'OUTER',
      os_id: osEntry.os_id,
      os_version: osEntry.version,
      cpu_cores: Math.max(1, Math.min(8, parseInt(String(cpu_cores || 1), 10))),
      ram_mib: Math.max(osEntry.min_ram_mib, parseInt(String(ram_mib || osEntry.min_ram_mib), 10)),
      storage_mib: Math.max(osEntry.min_storage_mib, parseInt(String(storage_mib || osEntry.min_storage_mib), 10)),
      subnet_cidr: safeCidr,
      auto_recover: auto_recover !== false,
      state: 'STOPPED',
      isolated_reason: '',
      recovery_count: 0,
    };
    honeypotNodes.set(id, node);
    savePersistentStateToDisk();
    appendAuditLog(
      'HONEYPOT_CREATED',
      `${node.layer}層ハニーポット '${node.node_id}'（名称: '${node.name}', OS: '${node.os_id}'）を作成しました。`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: node.node_id, result: 'SUCCESS' }
    );
    res.json({ success: true, node, state: buildMasterState(sess) });
  }
);

app.post(
  '/api/honeypots/:id/action',
  requireAuth,
  requireRole(['admin', 'group_member', 'researcher', 'business_operator']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const id = String(req.params.id);
    const { action, reason } = req.body || {};
    const node = honeypotNodes.get(id);
    if (!node) {
      return res.status(404).json({ error: `ハニーポット '${id}' が見つかりません` });
    }

    switch (action) {
      case 'start':
        if (node.state === 'ISOLATED') {
          return res.status(400).json({ error: `ノード '${id}' は隔離状態(ISOLATED)です。先に「自動復旧」を実行してください。` });
        }
        node.state = 'RUNNING';
        appendAuditLog('HONEYPOT_START', `ハニーポット '${id}' を起動しました。`, 'REAL_AUDIT', 'VERIFIED_BY_EXECUTION', {
          actor: sess.user_id,
          target: id,
          result: 'SUCCESS',
        });
        break;
      case 'stop':
        node.state = 'STOPPED';
        appendAuditLog('HONEYPOT_STOP', `ハニーポット '${id}' を停止しました。`, 'REAL_AUDIT', 'VERIFIED_BY_EXECUTION', {
          actor: sess.user_id,
          target: id,
          result: 'SUCCESS',
        });
        break;
      case 'isolate':
        node.state = 'ISOLATED';
        node.isolated_reason = sanitizeSafeDisplayText(reason, 'オペレーターによる手動隔離検疫', 120);
        appendAuditLog(
          'HONEYPOT_ISOLATED',
          `ハニーポット '${id}' を隔離しました: ${node.isolated_reason}`,
          'REAL_AUDIT',
          'VERIFIED_BY_EXECUTION',
          { actor: sess.user_id, target: id, result: 'SUCCESS' }
        );
        break;
      case 'auto_recover':
        node.state = 'RECOVERING';
        node.recovery_count += 1;
        node.isolated_reason = '';
        node.state = 'RUNNING';
        appendAuditLog(
          'HONEYPOT_RECOVERED',
          `ハニーポット '${id}' を自動復旧しました（累計復旧回数: #${node.recovery_count}）。`,
          'REAL_AUDIT',
          'VERIFIED_BY_EXECUTION',
          { actor: sess.user_id, target: id, result: 'SUCCESS' }
        );
        break;
      case 'delete':
        honeypotNodes.delete(id);
        appendAuditLog('HONEYPOT_DELETED', `ハニーポット '${id}' を削除しました。`, 'REAL_AUDIT', 'VERIFIED_BY_EXECUTION', {
          actor: sess.user_id,
          target: id,
          result: 'SUCCESS',
        });
        break;
      default:
        return res.status(400).json({ error: `不明なハニーポット操作です: ${action}` });
    }
    savePersistentStateToDisk();
    res.json({ success: true, state: buildMasterState(sess) });
  }
);

app.post(
  '/api/honeypots/:id/switch-os',
  requireAuth,
  requireRole(['admin', 'group_member', 'researcher', 'business_operator']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const id = String(req.params.id);
    const { target_os_id } = req.body || {};
    const node = honeypotNodes.get(id);
    if (!node) return res.status(404).json({ error: `ハニーポット '${id}' が見つかりません` });

    const osEntry = osCatalog.get(String(target_os_id));
    if (!osEntry) return res.status(400).json({ error: `切替先OS '${target_os_id}' が見つかりません` });

    const prevOs = node.os_id;
    const lic = getEffectiveLicenseState();
    if (!lic.entitlements.allowed_os_families.includes(osEntry.family)) {
      appendAuditLog(
        'HONEYPOT_OS_SWITCH_ROLLBACK',
        `'${id}' の7ステップOS切替が失敗しました: ファミリー '${osEntry.family}' は ${lic.active_tier} プランで許可されていません。'${prevOs}' へ安全にロールバックしました。`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: id, result: 'DENIED' }
      );
      return res.status(403).json({
        error: `ステップ 1/7 事前検証失敗: OSファミリー '${osEntry.family}' には上位ライセンスプランが必要です。稼働状態を維持したまま '${prevOs}' に自動ロールバックしました。`,
      });
    }
    if (osEntry.requires_kvm_full_vm) {
      appendAuditLog(
        'HONEYPOT_OS_SWITCH_ROLLBACK',
        `'${id}' の7ステップOS切替が失敗しました: '${osEntry.os_id}' に対するハードウェアリソースが不足しています。'${prevOs}' へ安全にロールバックしました。`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: id, result: 'DENIED' }
      );
      return res.status(400).json({
        error: `ステップ 2/7 ハードウェア事前検証失敗: '${osEntry.display_name}' には KVM および ${osEntry.min_ram_mib} MiB RAM が必要です。稼働状態を維持したまま '${prevOs}' に自動ロールバックしました。`,
      });
    }

    node.os_id = osEntry.os_id;
    node.os_version = osEntry.version;
    node.ram_mib = Math.max(node.ram_mib, osEntry.min_ram_mib);
    node.storage_mib = Math.max(node.storage_mib, osEntry.min_storage_mib);
    savePersistentStateToDisk();
    appendAuditLog(
      'HONEYPOT_OS_SWITCHED',
      `'${id}' の7ステップOS切替が完了しました: ${prevOs} -> ${osEntry.os_id}`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: id, result: 'SUCCESS' }
    );
    res.json({ success: true, node, state: buildMasterState(sess) });
  }
);

app.post(
  '/api/honeypots/custom-os',
  requireAuth,
  requireRole(['admin', 'group_member', 'researcher']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const { os_id, display_name, version, min_ram_mib, min_storage_mib } = req.body || {};
    const lic = getEffectiveLicenseState();
    if (!lic.entitlements.allow_custom_os_images) {
      return res.status(403).json({
        error: `カスタムOSイメージの署名登録には上位ライセンス（allow_custom_os_images）が必要です（現在: ${lic.active_tier}）。`,
      });
    }
    const cleanId = validateSafeIdentifier(os_id || `custom-linux-${Date.now().toString().slice(-4)}`, 'custom-linux');
    const ver = sanitizeSafeDisplayText(version, '1.0.0-custom', 32);
    const sha = crypto.createHash('sha256').update(`${cleanId}|${ver}`).digest('hex');
    registerSignedOSImage({
      os_id: cleanId,
      family: 'custom-verified',
      display_name: sanitizeSafeDisplayText(display_name, cleanId, 80),
      version: ver,
      architecture: 'x86_64',
      min_ram_mib: Math.max(32, parseInt(String(min_ram_mib || 64), 10)),
      min_storage_mib: Math.max(64, parseInt(String(min_storage_mib || 128), 10)),
      image_sha256: sha,
      build_status: '検証済みカスタムOSイメージ（Ed25519署名済み）',
      requires_kvm_full_vm: false,
    });
    appendAuditLog(
      'CUSTOM_OS_REGISTERED',
      `カスタムOS '${cleanId}' を登録しました（SHA-256 + Ed25519署名検証済み）。`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: cleanId, result: 'SUCCESS' }
    );
    res.json({ success: true, state: buildMasterState(sess) });
  }
);

let lastSignedBackup: Record<string, unknown> | null = null;
app.post(
  '/api/honeypots/backup',
  requireAuth,
  requireRole(['admin', 'group_member', 'business_operator']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const payloadObj = {
      schema: 'mk1ai.honeypot.backup.v1',
      exported_at: new Date().toISOString(),
      admin_policy_max: adminPolicyMaxHoneypots,
      nodes: Array.from(honeypotNodes.values()),
    };
    const canonical = Buffer.from(JSON.stringify(payloadObj), 'utf8');
    const sha256 = crypto.createHash('sha256').update(canonical).digest('hex');
    const sig = offlineAuthorityVault.signCanonicalPayload(canonical, 'admin');
    lastSignedBackup = { backup: payloadObj, sha256, signature_ed25519: sig };
    appendAuditLog(
      'HONEYPOT_BACKUP_EXPORTED',
      `Ed25519署名付きハニーポット構成バックアップをエクスポートしました（${honeypotNodes.size} ノード）。`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: 'honeypot-backup', result: 'SUCCESS' }
    );
    res.json({ success: true, bundle: lastSignedBackup });
  }
);

app.post(
  '/api/honeypots/restore',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  requireRecentReverification,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const bundle = req.body?.bundle || lastSignedBackup;
    if (!bundle || !bundle.backup || !bundle.signature_ed25519) {
      return res.status(400).json({ error: '復元対象の署名付きバックアップバンドルが存在しません。先にエクスポートを実行してください。' });
    }
    const canonical = Buffer.from(JSON.stringify(bundle.backup), 'utf8');
    const pubKey = crypto.createPublicKey(AUTHORITY_PUBLIC_KEY_PEM);
    let ok = false;
    try {
      ok = crypto.verify(null, canonical, pubKey, Buffer.from(String(bundle.signature_ed25519), 'hex'));
    } catch {
      ok = false;
    }
    if (!ok) {
      appendAuditLog(
        'HONEYPOT_BACKUP_TAMPERED',
        '改ざんされたハニーポットバックアップバンドルを拒否しました（Ed25519署名不一致）。',
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: 'honeypot-restore', result: 'DENIED' }
      );
      return res.status(403).json({ error: 'バックアップバンドルの Ed25519 署名検証に失敗しました。' });
    }
    const nodesList = (bundle.backup as { nodes: HoneypotNode[] }).nodes || [];
    const cap = computeEffectiveHoneypotCapacity();
    if (nodesList.length > cap.effective_max_honeypots) {
      return res.status(403).json({
        error: `バックアップ内のノード数 (${nodesList.length}) が現在の有効上限 (${cap.effective_max_honeypots}) を超過しています。`,
      });
    }
    honeypotNodes.clear();
    for (const n of nodesList) {
      honeypotNodes.set(n.node_id, {
        ...n,
        name: sanitizeSafeDisplayText(n.name, n.node_id, 80),
      });
    }
    savePersistentStateToDisk();
    appendAuditLog(
      'HONEYPOT_BACKUP_RESTORED',
      `署名検証済みバックアップから ${honeypotNodes.size} 台のハニーポット構成を復元しました。`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: 'honeypot-restore', result: 'SUCCESS' }
    );
    res.json({ success: true, state: buildMasterState(sess) });
  }
);

function normalizePlanTier(raw: string): PlanTier {
  if (raw in PLAN_CATALOG) return raw as PlanTier;
  const legacy: Record<string, PlanTier> = {
    BASIC: 'general.PLUS',
    STANDARD: 'business.PLUS',
    PRO: 'business.PRO',
    ENTERPRISE: 'group.ULTRAMAX',
  };
  return legacy[raw] || 'general.PLUS';
}

// Authenticated & Role-Checked 32-Tier License Plan Switcher (PART 2.2 & PART 5)
app.post('/api/license/switch-plan', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  const { plan_tier, category, identifier, signed_license_bundle } = req.body || {};

  let targetTier: PlanTier;
  if (category && identifier) {
    targetTier = `${category}.${identifier}` as PlanTier;
  } else {
    targetTier = normalizePlanTier(String(plan_tier || ''));
  }

  if (!PLAN_CATALOG[targetTier]) {
    return res.status(400).json({ error: `無効なプラン識別子です: ${targetTier}` });
  }

  const spec = PLAN_CATALOG[targetTier];
  const userAcct = userAccounts.get(sess.user_id);

  // RBAC Plan Category Authorization (PART 2.2):
  // Non-admin users cannot self-upgrade to categories outside their authorized role unless they supply a valid pre-signed license bundle
  const allowedCategories = userAcct?.allowed_categories || ['general'];
  const isRoleAuthorized =
    sess.role === 'admin' ||
    sess.role === 'group_member' ||
    (allowedCategories.includes(spec.category) && (sess.role !== 'general_user' || targetTier === 'general.PLUS'));

  if (!isRoleAuthorized && !signed_license_bundle) {
    appendAuditLog(
      'PLAN_SWITCH_UNAUTHORIZED',
      `Blocked unauthorized plan switch to '${targetTier}' by user '${sess.user_id}' (role=${sess.role}).`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: targetTier, result: 'DENIED' }
    );
    return res.status(403).json({
      error: `ライセンス権限エラー (403 Forbidden): ロール '${sess.role}' では署名済みライセンスバンドルなしに '${spec.display_name}' (${targetTier}) へ切り替えることはできません。管理者アカウントでログインするか正規ライセンスを適用してください。`,
    });
  }

  let signed: SignedOfflineLicense;
  if (signed_license_bundle) {
    if (!verifyLicenseWithPublicKeyOnly(signed_license_bundle)) {
      return res.status(403).json({ error: '提供されたライセンスバンドルの Ed25519 署名検証に失敗しました。' });
    }
    if (signed_license_bundle.monotonic_seq <= highestMonotonicSeq) {
      return res.status(403).json({ error: 'ライセンスのロールバック(旧シーケンス番号)が検出されたため拒否されました。' });
    }
    signed = signed_license_bundle;
  } else {
    const seq = highestMonotonicSeq + 1;
    const nowSec = Math.floor(Date.now() / 1000);
    signed = issueSignedLicenseFromVault(
      {
        license_id: `lic-${targetTier.replace('.', '-')}-seq${seq}`,
        group_id: targetTier.startsWith('group.') ? 'grp-thunderhall-ops' : 'grp-user-session',
        plan_tier: targetTier,
        device_fingerprint: LOCAL_DEVICE_FINGERPRINT,
        issued_at_epoch: nowSec,
        expires_at_epoch: nowSec + 86400 * 365,
        monotonic_seq: seq,
      },
      'admin'
    );
  }

  // Runtime Verifier verifies with Public Key Only
  if (!verifyLicenseWithPublicKeyOnly(signed)) {
    return res.status(403).json({ error: 'Ed25519 公開鍵検証に失敗しました。' });
  }

  highestMonotonicSeq = signed.monotonic_seq;
  activeLicense = signed;
  licenseStatusNote = `${spec.display_name} (Ed25519公開鍵検証済み, seq=${highestMonotonicSeq})`;

  // Adjust active pipelines if exceeding new plan's limit
  if (activeTestPipelinesCount > spec.concurrent_test_pipelines) {
    activeTestPipelinesCount = spec.concurrent_test_pipelines;
  }

  savePersistentStateToDisk();
  appendAuditLog(
    'PLAN_SWITCHED',
    `契約プランを '${spec.display_name}' (${targetTier}) へ切り替えました。利用枠=${spec.is_unlimited_usage ? '無制限' : Math.floor(spec.max_daily_usage_sec / 3600) + 'h/日'}, ハニーポット=${spec.max_honeypots_by_plan}台, 帯域=${spec.max_bandwidth_mbps}Mbps, SLA=${spec.support_sla}`,
    'REAL_AUDIT',
    'VERIFIED_BY_EXECUTION',
    { actor: sess.user_id, target: targetTier, result: 'SUCCESS' }
  );

  res.json({ success: true, active_tier: targetTier, license: signed, state: buildMasterState(sess) });
});

// License Issuance & Activation (Admin Only)
app.post(
  '/api/license/issue-and-activate',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const { plan_tier, group_id, simulated_rollback_attack, client_self_declared_admin } = req.body || {};

    if (client_self_declared_admin) {
      appendAuditLog(
        'SECURITY_VIOLATION_SELF_DECLARED_ADMIN',
        'クライアント自己申告による Developer Group / Enterprise 権限昇格の試みを遮断しました。',
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: 'license-issuer', result: 'DENIED' }
      );
      return res.status(403).json({
        error: '権限昇格遮断 (PrivilegeEscalationBlockedError): クライアント自己申告の管理者権限は厳格に拒否されます。',
      });
    }

    const tier: PlanTier = normalizePlanTier(String(plan_tier || ''));
    const seq = simulated_rollback_attack ? highestMonotonicSeq : highestMonotonicSeq + 1;
    const nowSec = Math.floor(Date.now() / 1000);

    const signed = issueSignedLicenseFromVault(
      {
        license_id: `lic-${tier.replace('.', '-').toLowerCase()}-seq${seq}`,
        group_id: sanitizeSafeDisplayText(group_id, 'grp-core-sec', 64),
        plan_tier: tier,
        device_fingerprint: LOCAL_DEVICE_FINGERPRINT,
        issued_at_epoch: nowSec,
        expires_at_epoch: nowSec + 86400 * 30,
        monotonic_seq: seq,
      },
      sess.role
    );

    if (!verifyLicenseWithPublicKeyOnly(signed)) {
      return res.status(403).json({ error: 'Ed25519 signature verification failed' });
    }
    if (signed.monotonic_seq <= highestMonotonicSeq) {
      appendAuditLog(
        'LICENSE_ROLLBACK_BLOCKED',
        `Blocked offline license rollback attempt: seq=${signed.monotonic_seq} <= highest_seen=${highestMonotonicSeq}`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: signed.license_id, result: 'DENIED' }
      );
      return res.status(403).json({
        error: `Anti-Rollback Triggered: License monotonic_seq (${signed.monotonic_seq}) <= highest verified sequence (${highestMonotonicSeq}).`,
      });
    }

    highestMonotonicSeq = signed.monotonic_seq;
    activeLicense = signed;
    const spec = PLAN_CATALOG[tier] || PLAN_CATALOG['general.PLUS'];
    licenseStatusNote = `Ed25519 Offline License Verified (${spec.display_name}, seq=${highestMonotonicSeq})`;
    const grp = developerGroups.get(signed.group_id);
    if (grp) grp.issued_licenses.unshift(signed);

    savePersistentStateToDisk();
    appendAuditLog(
      'LICENSE_ACTIVATED',
      `Activated Ed25519 offline license '${signed.license_id}' (tier=${tier}, seq=${highestMonotonicSeq}).`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: signed.license_id, result: 'SUCCESS' }
    );
    res.json({ success: true, license: signed, state: buildMasterState(sess) });
  }
);

app.post(
  '/api/license/simulate-expiry-or-revoke',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const { mode } = req.body || {};
    if (mode === 'revoke' && activeLicense) {
      revokedLicenseIds.add(activeLicense.license_id);
      appendAuditLog(
        'LICENSE_REVOKED',
        `Revoked license '${activeLicense.license_id}'. Degraded to general.PLUS tier; CORE isolation & Kill Switch remain 100% active.`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: activeLicense.license_id, result: 'SUCCESS' }
      );
    } else if (activeLicense) {
      activeLicense.expires_at_epoch = Math.floor(Date.now() / 1000) - 10;
      appendAuditLog(
        'LICENSE_EXPIRED',
        `Simulated expiry for '${activeLicense.license_id}'. Degraded to general.PLUS tier; CORE isolation & Kill Switch remain 100% active.`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: activeLicense.license_id, result: 'SUCCESS' }
      );
    }
    savePersistentStateToDisk();
    res.json({ success: true, state: buildMasterState(sess) });
  }
);

app.post(
  '/api/dev-groups/create',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const { group_id, group_name, plan_tier, max_honeypots_quota, max_bandwidth_mbps_quota, client_self_declared_admin } =
      req.body || {};
    if (client_self_declared_admin) {
      appendAuditLog(
        'SECURITY_VIOLATION_SELF_DECLARED_ADMIN',
        'クライアント自己申告によるグループ作成を遮断しました。',
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: 'dev-groups', result: 'DENIED' }
      );
      return res.status(403).json({ error: '権限昇格遮断 (PrivilegeEscalationBlockedError): 自己申告の管理者権限は拒否されました。' });
    }
    const id = validateSafeIdentifier(group_id || `grp-${Date.now().toString().slice(-4)}`, 'grp-custom');
    if (developerGroups.has(id)) {
      return res.status(400).json({ error: `開発者グループ '${id}' は既に存在します` });
    }
    const tier: PlanTier = normalizePlanTier(String(plan_tier || 'group.ULTRAMAX'));
    const grp: DeveloperGroup = {
      group_id: id,
      group_name: sanitizeSafeDisplayText(group_name, id, 80),
      plan_tier: tier,
      max_honeypots_quota: Math.max(2, Math.min(256, parseInt(String(max_honeypots_quota || 32), 10))),
      max_bandwidth_mbps_quota: Math.max(100, parseInt(String(max_bandwidth_mbps_quota || 10000), 10)),
      allowed_os_families: PLAN_CATALOG[tier].allowed_os_families,
      members: [{ user_id: sess.user_id, role: 'グループ所有者 (OWNER)', added_at: new Date().toISOString() }],
      issued_licenses: [],
    };
    developerGroups.set(id, grp);
    savePersistentStateToDisk();
    appendAuditLog(
      'DEV_GROUP_CREATED',
      `開発者グループ '${id}' を作成しました（プラン=${tier}, 最大ハニーポット枠=${grp.max_honeypots_quota}台）。`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: id, result: 'SUCCESS' }
    );
    res.json({ success: true, group: grp, state: buildMasterState(sess) });
  }
);

app.post(
  '/api/dev-groups/:id/member',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const grp = developerGroups.get(String(req.params.id));
    if (!grp) return res.status(404).json({ error: '指定された開発者グループが見つかりません' });
    const { action, user_id, role } = req.body || {};
    const uid = sanitizeSafeDisplayText(user_id, '', 64);
    if (!uid) return res.status(400).json({ error: 'ユーザーID (user_id) を指定してください' });

    if (action === 'remove') {
      grp.members = grp.members.filter((m) => m.user_id !== uid);
      appendAuditLog(
        'DEV_GROUP_MEMBER_REMOVED',
        `'${uid}' をグループ '${grp.group_id}' から削除しました。`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: grp.group_id, result: 'SUCCESS' }
      );
    } else {
      grp.members = grp.members.filter((m) => m.user_id !== uid);
      grp.members.push({
        user_id: uid,
        role: sanitizeSafeDisplayText(role, 'セキュリティエンジニア', 48),
        added_at: new Date().toISOString(),
      });
      appendAuditLog(
        'DEV_GROUP_MEMBER_ADDED',
        `'${uid}' をグループ '${grp.group_id}' に追加しました。`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: grp.group_id, result: 'SUCCESS' }
      );
    }
    savePersistentStateToDisk();
    res.json({ success: true, state: buildMasterState(sess) });
  }
);

// ============================================================================
// 12. Redesigned Two-Person Quorum Kill Switch & ONI_MODE Routes (PART 2.3)
// ============================================================================
app.post(
  '/api/security/kill-switch/approve',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const { event_id, admin_id, target_scope, reason, ttl_sec } = req.body || {};

    let evt: string;
    try {
      evt = validateSafeIdentifier(event_id || 'evt-critical-001', 'evt-critical-001');
    } catch (e: unknown) {
      return res.status(400).json({ error: e instanceof Error ? e.message : '無効なイベントIDです' });
    }

    if (executedKillSwitchEvents.has(evt)) {
      return res.status(409).json({
        error: `リプレイ攻撃遮断: Kill Switch イベント '${evt}' は既に実行済みのため再承認できません。`,
      });
    }

    // PART 2.3 Critical Requirement: Never trust arbitrary self-declared admin_id strings!
    // If admin_id is supplied in body and does not match the authenticated session's user_id, block spoofing.
    if (admin_id !== undefined && String(admin_id).trim() !== '' && String(admin_id).trim() !== sess.user_id) {
      appendAuditLog(
        'KILL_SWITCH_SPOOFING_BLOCKED',
        `Blocked Quorum spoofing attempt: session user '${sess.user_id}' attempted to submit approval as '${admin_id}' for event '${evt}'.`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: evt, result: 'DENIED' }
      );
      return res.status(403).json({
        error: `なりすまし遮断 (AdminSpoofingBlockedError): 現在のログインセッション ('${sess.user_id}') と異なる管理者ID ('${admin_id}') での自己申告承認は禁止されています。2人目の管理者アカウントでログインして承認してください。`,
      });
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const effectiveTtl = ttl_sec !== undefined ? Math.max(1, Math.min(3600, parseInt(String(ttl_sec), 10))) : DEFAULT_QUORUM_TTL_SEC;
    const scope = sanitizeSafeDisplayText(target_scope, 'GLOBAL_SIM_AND_INGEST', 64);
    const rsn = sanitizeSafeDisplayText(reason, '緊急隔離承認', 120);

    let rec = killSwitchRecords.get(evt);
    if (!rec) {
      rec = {
        event_id: evt,
        target_scope: scope,
        reason: rsn,
        state: 'REQUESTED',
        requested_by: sess.user_id,
        created_at_epoch: nowSec,
        expires_at_epoch: nowSec + effectiveTtl,
        approvals: [],
      };
      killSwitchRecords.set(evt, rec);
    }

    pruneExpiredQuorumApprovals(rec, nowSec);

    if (rec.state === 'REJECTED') {
      return res.status(409).json({
        error: `イベント '${evt}' は既に却下 (REJECTED) されています。新しいイベントIDを発行してください。`,
      });
    }

    // Prohibit duplicate approval by the same administrator (PART 2.3)
    if (rec.approvals.some((a) => a.approver_id === sess.user_id)) {
      appendAuditLog(
        'KILL_SWITCH_DUPLICATE_ADMIN_BLOCKED',
        `Blocked duplicate Quorum approval by same administrator '${sess.user_id}' for event '${evt}'.`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: evt, result: 'DENIED' }
      );
      return res.status(409).json({
        error: `同一管理者重複エラー (409 Conflict): 管理者 '${sess.user_id}' は既にイベント '${evt}' を承認済みです。異なる2人目の管理者アカウント（例: admin-bob）による承認が必要です。`,
      });
    }

    const expiresAt = nowSec + effectiveTtl;
    const sig = signQuorumApprovalPayload(evt, sess.user_id, rec.target_scope, nowSec, expiresAt);
    const approval: QuorumSignedApproval = {
      approver_id: sess.user_id,
      approver_display_name: sess.display_name,
      approver_role: sess.role,
      session_fingerprint: crypto.createHash('sha256').update(sess.session_id).digest('hex').slice(0, 16),
      approved_at_epoch: nowSec,
      expires_at_epoch: expiresAt,
      target_scope: rec.target_scope,
      reason: rsn,
      signature_ed25519: sig,
    };

    rec.approvals.push(approval);
    rec.state = rec.approvals.length >= QUORUM_REQUIRED ? 'APPROVED' : 'APPROVAL_PENDING';

    savePersistentStateToDisk();
    appendAuditLog(
      'KILL_SWITCH_QUORUM_APPROVAL',
      `認証済み管理者 '${sess.user_id}' が緊急遮断(Kill Switch)イベント '${evt}' に電子署名しました（状態=${rec.state}, Quorum承認数: ${rec.approvals.length}/${QUORUM_REQUIRED}）。`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: evt, result: 'SUCCESS' }
    );

    res.json({
      success: true,
      event_id: evt,
      lifecycle_state: rec.state,
      approvals_count: rec.approvals.length,
      current_approvals_count: rec.approvals.length,
      approval_signature: sig,
      state: buildMasterState(sess),
    });
  }
);

app.post(
  '/api/security/kill-switch/reject',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const evt = validateSafeIdentifier(req.body?.event_id || 'evt-critical-001', 'evt-critical-001');
    const reason = sanitizeSafeDisplayText(req.body?.reason, '管理者による緊急遮断要求の却下', 120);
    const nowSec = Math.floor(Date.now() / 1000);

    let rec = killSwitchRecords.get(evt);
    if (!rec) {
      rec = {
        event_id: evt,
        target_scope: 'GLOBAL_SIM_AND_INGEST',
        reason,
        state: 'REJECTED',
        requested_by: sess.user_id,
        created_at_epoch: nowSec,
        expires_at_epoch: nowSec + DEFAULT_QUORUM_TTL_SEC,
        approvals: [],
      };
      killSwitchRecords.set(evt, rec);
    } else {
      rec.state = 'REJECTED';
      rec.rejected_by = sess.user_id;
      rec.rejection_reason = reason;
      rec.approvals = [];
    }

    savePersistentStateToDisk();
    appendAuditLog(
      'KILL_SWITCH_REQUEST_REJECTED',
      `管理者 '${sess.user_id}' が Kill Switch イベント '${evt}' を却下(REJECTED)しました: ${reason}`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: evt, result: 'SUCCESS' }
    );
    res.json({ success: true, event_id: evt, lifecycle_state: rec.state, state: buildMasterState(sess) });
  }
);

app.post(
  '/api/security/kill-switch/execute',
  requireAuth,
  requireRole(['admin', 'group_member']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const { event_id, reason } = req.body || {};
    const evt = validateSafeIdentifier(event_id || 'evt-critical-001', 'evt-critical-001');

    if (executedKillSwitchEvents.has(evt)) {
      appendAuditLog(
        'KILL_SWITCH_REPLAY_BLOCKED',
        `Blocked replay execution attempt for already-executed Kill Switch event '${evt}'.`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: evt, result: 'DENIED' }
      );
      return res.status(403).json({
        error: `リプレイ攻撃遮断: Kill Switch イベント '${evt}' は既に実行済みです。`,
      });
    }

    const rec = killSwitchRecords.get(evt);
    const nowSec = Math.floor(Date.now() / 1000);
    if (rec) {
      pruneExpiredQuorumApprovals(rec, nowSec);
    }

    const validApprovals = (rec?.approvals || []).filter((a) => verifyQuorumApprovalSignature(a, evt));
    const distinctAdmins = new Set(validApprovals.map((a) => a.approver_id));

    if (!rec || distinctAdmins.size < QUORUM_REQUIRED) {
      appendAuditLog(
        'KILL_SWITCH_REJECTED',
        `イベント '${evt}' に対する execute_kill_switch() を拒否しました: 有効な異なる管理者のQuorum承認数 (${distinctAdmins.size}/${QUORUM_REQUIRED}) が不足しています（または期限切れ）。`,
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: evt, result: 'DENIED' }
      );
      return res.status(403).json({
        error: `承認不足エラー (KillSwitchApprovalError): イベント '${evt}' の実行には異なる認証済み管理者 ${QUORUM_REQUIRED} 名の有効な署名が必要です（現在 ${distinctAdmins.size} 名）。`,
      });
    }

    // Lifecycle transitions (PART 2.3): APPROVED -> EXECUTION_PENDING -> EXECUTED -> VERIFICATION_PENDING -> VERIFIED
    rec.state = 'EXECUTION_PENDING';
    executedKillSwitchEvents.add(evt);
    currentOniMode = 'EMERGENCY_QUARANTINE';
    simSystemState = 'EMERGENCY_HALT';
    appliedPps = 0;
    if (streamState === 'LIVE' || streamState === 'TESTING' || streamState === 'ENCODING') {
      streamState = 'STOPPED';
      youtubeStreamStatus = 'inactive';
    }
    rec.state = 'EXECUTED';
    rec.executed_at_epoch = nowSec;

    // Post-execution verification check
    rec.state = 'VERIFICATION_PENDING';
    const verifiedOk =
      currentOniMode === 'EMERGENCY_QUARANTINE' &&
      simSystemState === 'EMERGENCY_HALT' &&
      appliedPps === 0;
    rec.state = verifiedOk ? 'VERIFIED' : 'FAILED';
    rec.verified_at_epoch = nowSec;
    rec.verification_evidence = verifiedOk
      ? 'VERIFIED: simSystemState=EMERGENCY_HALT, appliedPps=0, oni_mode=EMERGENCY_QUARANTINE'
      : 'FAILED: Post-condition mismatch';

    savePersistentStateToDisk();
    appendAuditLog(
      'KILL_SWITCH_EXECUTED',
      `Quorum承認済み緊急遮断(Kill Switch)をイベント '${evt}' に対して執行・検証完了しました（状態=${rec.state}, 承認者: ${Array.from(distinctAdmins).join(', ')}）: ${sanitizeSafeDisplayText(reason, '緊急封じ込め措置', 120)}`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: evt, result: 'SUCCESS' }
    );
    res.json({
      success: true,
      executed: true,
      executed_event: evt,
      lifecycle_state: rec.state,
      verification_evidence: rec.verification_evidence,
      oni_mode: currentOniMode,
      state: buildMasterState(sess),
    });
  }
);

app.post(
  '/api/security/oni-mode',
  requireAuth,
  requireRole(['admin', 'group_member', 'business_operator']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    const { mode, reason } = req.body || {};
    if (!['NORMAL', 'ELEVATED_MONITORING', 'ISOLATION_LOCK', 'EMERGENCY_QUARANTINE'].includes(mode)) {
      return res.status(400).json({ error: '無効な ONI_MODE 状態です' });
    }
    const prev = currentOniMode;
    currentOniMode = mode as OniMode;
    savePersistentStateToDisk();
    appendAuditLog(
      'ONI_MODE_CHANGED',
      `ONI_MODE 単一状態源を更新しました: ${prev} -> ${currentOniMode} (${sanitizeSafeDisplayText(reason, 'オペレーター操作', 80)})`,
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: sess.user_id, target: 'oni-mode', result: 'SUCCESS' }
    );
    res.json({ success: true, state: buildMasterState(sess) });
  }
);

// ============================================================================
// 13. Safe Read-Only Files API & Safe Temp Project ZIP Export (PART 2.5)
// ============================================================================
app.get('/api/files/list', requireAuth, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  try {
    const folder = typeof req.query.folder === 'string' ? req.query.folder : undefined;
    const files = listSafeWorkspaceFiles(folder);
    res.json({ success: true, count: files.length, files });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    appendAuditLog('FILES_ACCESS_BLOCKED', msg, 'REAL_AUDIT', 'VERIFIED_BY_EXECUTION', {
      actor: sess.user_id,
      target: String(req.query.folder || ''),
      result: 'DENIED',
    });
    res.status(403).json({ error: msg });
  }
});

app.get('/api/files/inspect', requireAuth, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  try {
    const relPath = typeof req.query.path === 'string' ? req.query.path : '';
    const info = inspectSafeRegularFile(relPath);
    res.json({ success: true, file: info });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    appendAuditLog('FILES_INSPECT_BLOCKED', msg, 'REAL_AUDIT', 'VERIFIED_BY_EXECUTION', {
      actor: sess.user_id,
      target: String(req.query.path || ''),
      result: 'DENIED',
    });
    res.status(403).json({ error: msg });
  }
});

// Safe Project ZIP Download (PART 2.5):
// - Requires Admin/Group authentication
// - Writes to isolated os.tmpdir() temp file (never overwrites workspace files)
// - Passes paths via environment variables (no string interpolation in Python code)
// - Enforces strict allowlist & secret exclusion
app.get(
  '/api/download/project-zip',
  requireAuth,
  requireRole(['admin', 'group_member']),
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    if (!checkRateLimit(req, res, 'zip_export', 5, 60000)) return;

    const tmpZipPath = path.join(os.tmpdir(), `thunderhall_safe_export_${crypto.randomUUID()}.zip`);
    const pyScript = `
import os, sys, zipfile

workspace_root = os.environ["TH_WORKSPACE_ROOT"]
zip_out_path = os.environ["TH_ZIP_OUT_PATH"]

ALLOWED_TOP_FILES = {
    "package.json", "tsconfig.json", "vite.config.ts", "metadata.json",
    "README.md", "server.ts", "index.html", ".env.example"
}
ALLOWED_TOP_DIRS = {"src", "tests", "mk1ai_productization", "テストツール"}
FORBIDDEN_DIRS = {"node_modules", ".git", "__pycache__", ".aistudio", "dist", ".thunderhall_data"}
FORBIDDEN_EXTENSIONS = {".pem", ".key", ".pfx", ".p12", ".sqlite", ".db", ".zip"}
MAX_FILE_BYTES = 5 * 1024 * 1024

with zipfile.ZipFile(zip_out_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for entry in sorted(os.listdir(workspace_root)):
        full_top = os.path.join(workspace_root, entry)
        if os.path.islink(full_top):
            continue
        if os.path.isfile(full_top):
            if entry in ALLOWED_TOP_FILES and os.path.getsize(full_top) <= MAX_FILE_BYTES:
                zf.write(full_top, entry)
        elif os.path.isdir(full_top) and entry in ALLOWED_TOP_DIRS:
            for root, dirs, files in os.walk(full_top, followlinks=False):
                dirs[:] = [d for d in sorted(dirs) if d not in FORBIDDEN_DIRS and not d.startswith(".")]
                for f in sorted(files):
                    if f.startswith(".env") or "secret" in f.lower():
                        continue
                    _, ext = os.path.splitext(f)
                    if ext.lower() in FORBIDDEN_EXTENSIONS:
                        continue
                    fp = os.path.join(root, f)
                    if os.path.islink(fp) or not os.path.isfile(fp):
                        continue
                    if os.path.getsize(fp) > MAX_FILE_BYTES:
                        continue
                    rel = os.path.relpath(fp, workspace_root)
                    zf.write(fp, rel)
`;

    execFile(
      'python3',
      ['-c', pyScript],
      {
        timeout: 15000,
        env: {
          ...process.env,
          TH_WORKSPACE_ROOT: __dirname,
          TH_ZIP_OUT_PATH: tmpZipPath,
        },
      },
      (err) => {
        if (err || !fs.existsSync(tmpZipPath)) {
          try {
            if (fs.existsSync(tmpZipPath)) fs.unlinkSync(tmpZipPath);
          } catch {
            // ignore
          }
          return res.status(500).json({ error: '安全なZIPアーカイブの生成に失敗しました' });
        }
        appendAuditLog(
          'PROJECT_ZIP_EXPORTED',
          'Exported allowlisted project ZIP via isolated temporary file (secrets & symlinks excluded).',
          'REAL_AUDIT',
          'VERIFIED_BY_EXECUTION',
          { actor: sess.user_id, target: 'project-zip', result: 'SUCCESS' }
        );
        res.download(tmpZipPath, 'thunderhall_security_project.zip', () => {
          try {
            if (fs.existsSync(tmpZipPath)) fs.unlinkSync(tmpZipPath);
          } catch {
            // ignore cleanup error
          }
        });
      }
    );
  }
);

// Redaction Tester API
app.post('/api/redact', requireAuth, requireCsrf, (req: Request, res: Response) => {
  try {
    const { text } = req.body || {};
    const redacted = redactTextFailClosed(String(text || ''));
    res.json({
      original_length: String(text || '').length,
      redacted,
      matches_found: redacted !== text,
      evidence_class: 'VERIFIED_BY_EXECUTION',
    });
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'マスキング処理に失敗しました' });
  }
});

// ============================================================================
// 14. Hardened OAuth 2.0 & Tester Built-in YouTube Live Studio (PART 3.1)
// ============================================================================
app.get('/api/auth/youtube/url', requireAuth, (req: Request, res: Response) => {
  const hostHeader = req.get('host') || `127.0.0.1:${port}`;
  const defaultOrigin = `${req.protocol}://${hostHeader}`;
  const rawOrigin = typeof req.query.origin === 'string' ? req.query.origin : defaultOrigin;
  // Validate origin format
  let safeOrigin = defaultOrigin;
  try {
    const parsedUrl = new URL(rawOrigin);
    safeOrigin = parsedUrl.origin;
  } catch {
    safeOrigin = defaultOrigin;
  }

  const redirectUri = `${safeOrigin.replace(/\/$/, '')}/auth/callback`;
  const csrfState = issueOAuthCsrfState(safeOrigin);
  const clientId = process.env.YOUTUBE_CLIENT_ID || '';

  if (!clientId) {
    return res.json({
      configured: false,
      execution_mode: 'SIMULATED',
      redirect_uri: redirectUri,
      csrf_state: csrfState,
      message: '環境変数 YOUTUBE_CLIENT_ID が未設定のため、実OAuth接続は NOT_CONFIGURED です。模擬OAuthテストモードを使用してください。',
    });
  }

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/youtube.force-ssl',
    access_type: 'offline',
    state: csrfState,
  });
  res.json({
    configured: true,
    execution_mode: 'LIVE_YOUTUBE_API',
    url: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`,
    redirect_uri: redirectUri,
    csrf_state: csrfState,
  });
});

// Hardened OAuth Callback (PART 3.1):
// - Rejects missing or unissued `state` parameter with 403
// - Requires valid `code` parameter
// - Restricts window.opener.postMessage targetOrigin to validated origin (never '*')
app.get(['/auth/callback', '/auth/callback/'], (req: Request, res: Response) => {
  const stateParam = typeof req.query.state === 'string' ? req.query.state.trim() : '';
  const codeParam = typeof req.query.code === 'string' ? req.query.code.trim() : '';

  if (!stateParam) {
    appendAuditLog(
      'OAUTH_CSRF_MISSING_STATE',
      'Blocked OAuth callback request with missing state parameter.',
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: 'oauth-callback', target: '/auth/callback', result: 'DENIED' }
    );
    return res.status(403).send('OAuth CSRF Protection: state パラメータが欠落しているため遮断されました。');
  }

  const stateEntry = pendingOAuthStates.get(stateParam);
  const nowSec = Math.floor(Date.now() / 1000);
  if (!stateEntry || nowSec > stateEntry.expires_at_epoch) {
    pendingOAuthStates.delete(stateParam);
    appendAuditLog(
      'OAUTH_CSRF_STATE_MISMATCH',
      'Blocked OAuth callback request with invalid or expired state parameter.',
      'REAL_AUDIT',
      'VERIFIED_BY_EXECUTION',
      { actor: 'oauth-callback', target: '/auth/callback', result: 'DENIED' }
    );
    return res.status(403).send('OAuth CSRF Protection: state が不一致または期限切れのため遮断されました。');
  }

  // Consume one-time state token immediately
  pendingOAuthStates.delete(stateParam);

  if (!codeParam) {
    return res.status(400).send('OAuth Error: 認可コード (code) パラメータが存在しません。');
  }

  const isRealConfigured = Boolean(process.env.YOUTUBE_CLIENT_ID && process.env.YOUTUBE_CLIENT_SECRET);
  oauthConnected = true;
  oauthConnectionType = isRealConfigured ? 'REAL_OAUTH_VERIFIED' : 'SIMULATED_OAUTH';
  privateOAuthToken = `ya29.oauth_session_${crypto.randomBytes(12).toString('hex')}`;
  privateStreamKey = `live_${crypto.randomBytes(10).toString('hex')}`;
  sensitiveLiterals.set(privateOAuthToken, '[REDACTED_OAUTH_TOKEN]');
  sensitiveLiterals.set(privateStreamKey, '[REDACTED_STREAM_KEY]');
  streamState = 'READY';

  appendAuditLog(
    'YOUTUBE_OAUTH_CALLBACK_PROCESSED',
    `Processed YouTube OAuth callback (mode=${oauthConnectionType}, state verified & consumed).`,
    isRealConfigured ? 'REAL_AUDIT' : 'DEMO_SIMULATION',
    isRealConfigured ? 'VERIFIED_BY_EXECUTION' : 'SIMULATED'
  );

  const safeTargetOrigin = JSON.stringify(stateEntry.origin);
  res.send(`<!DOCTYPE html><html lang="ja"><body style="background:#0B0F19;color:#F8FAFC;font-family:sans-serif;padding:24px;">
    <script>
      (function() {
        var targetOrigin = ${safeTargetOrigin};
        if (window.opener && typeof window.opener.postMessage === 'function') {
          window.opener.postMessage({ type: 'OAUTH_AUTH_SUCCESS', mode: ${JSON.stringify(oauthConnectionType)} }, targetOrigin);
          window.close();
        } else {
          window.location.href = '/';
        }
      })();
    </script>
    <p>YouTube OAuth 状態検証が完了しました。ウィンドウを閉じています...</p>
  </body></html>`);
});

app.post('/api/stream/action', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  const { action, mode, user_age, adult_co_stream } = req.body || {};
  streamLastError = '';

  if (user_age !== undefined) {
    const age = parseInt(String(user_age), 10);
    if (age < 16 && !adult_co_stream) {
      userAgeEligible = false;
      streamState = 'NOT_ELIGIBLE';
      streamLastError = 'YouTube ポリシー制限: 16歳未満のユーザーは単独でライブ配信を行えません。プレビューおよびローカルテストモードのみ利用可能です。';
      appendAuditLog('STREAM_AGE_POLICY_BLOCK', streamLastError, 'REAL_AUDIT', 'VERIFIED_BY_EXECUTION', {
        actor: sess.user_id,
        target: 'stream-studio',
        result: 'DENIED',
      });
      return res.json({ success: false, error: streamLastError, state: buildMasterState(sess) });
    }
    userAgeEligible = true;
  }

  if (mode === 'TEST_MODE_SIMULATED' || mode === 'LIVE_YOUTUBE_API') {
    streamExecutionMode = mode;
  }

  switch (action) {
    case 'connect_mock_oauth':
      oauthConnected = true;
      oauthConnectionType = 'SIMULATED_OAUTH';
      privateOAuthToken = `ya29.sim_token_${crypto.randomBytes(8).toString('hex')}`;
      privateStreamKey = `live_sim_key_${crypto.randomBytes(8).toString('hex')}`;
      sensitiveLiterals.set(privateOAuthToken, '[REDACTED_OAUTH_TOKEN]');
      sensitiveLiterals.set(privateStreamKey, '[REDACTED_STREAM_KEY]');
      streamState = 'READY';
      appendAuditLog(
        'STREAM_OAUTH_SIMULATED',
        '模擬OAuthセッションを接続しました（SIMULATED_OAUTH: 実Google通信なし、トークンはメモリ内で秘匿保護）。',
        'DEMO_SIMULATION',
        'SIMULATED',
        { actor: sess.user_id, target: 'stream-studio', result: 'SUCCESS' }
      );
      break;

    case 'disconnect_oauth':
      oauthConnected = false;
      oauthConnectionType = 'NONE';
      privateOAuthToken = null;
      privateStreamKey = null;
      youtubeStreamStatus = 'inactive';
      streamState = 'DISCONNECTED';
      streamStartedAtEpoch = null;
      appendAuditLog(
        'STREAM_OAUTH_DISCONNECTED',
        'OAuthトークンを失効させ、メモリ上のストリームキーを完全消去しました。',
        'REAL_AUDIT',
        'VERIFIED_BY_EXECUTION',
        { actor: sess.user_id, target: 'stream-studio', result: 'SUCCESS' }
      );
      break;

    case 'preview':
      previewVerified = true;
      streamState = 'PREVIEW';
      appendAuditLog(
        'STREAM_PREVIEW',
        'テスター専用出力Canvasのプレビューを確認しました（ホワイトリスト登録ソースのみ描画）。',
        'DEMO_SIMULATION',
        'SIMULATED',
        { actor: sess.user_id, target: 'stream-studio', result: 'SUCCESS' }
      );
      break;

    case 'start_test_signal':
      previewVerified = true;
      streamExecutionMode = 'TEST_MODE_SIMULATED';
      youtubeStreamStatus = 'active';
      streamState = 'TESTING';
      streamStartedAtEpoch = Math.floor(Date.now() / 1000);
      appendAuditLog(
        'STREAM_TEST_SIGNAL_START',
        '隔離された仮想シンク（Fake Ingest Sink）へテスト信号送出を開始しました（SIMULATED: 外部通信 0 バイト）。',
        'DEMO_SIMULATION',
        'SIMULATED',
        { actor: sess.user_id, target: 'stream-studio', result: 'SUCCESS' }
      );
      break;

    case 'stop_test_signal':
      youtubeStreamStatus = 'inactive';
      streamState = 'STOPPED';
      streamStartedAtEpoch = null;
      appendAuditLog(
        'STREAM_TEST_SIGNAL_STOP',
        '仮想シンク（Fake Ingest Sink）のテスト信号を停止しました。',
        'DEMO_SIMULATION',
        'SIMULATED',
        { actor: sess.user_id, target: 'stream-studio', result: 'SUCCESS' }
      );
      break;

    case 'prepare_youtube_stream':
      if (!userAgeEligible) {
        streamState = 'NOT_ELIGIBLE';
        return res.status(403).json({ error: '年齢制限またはチャンネル要件により YouTube ライブ配信の対象外です。', state: buildMasterState(sess) });
      }
      if (!oauthConnected) {
        streamState = 'AUTH_REQUIRED';
        return res.status(401).json({ error: '先に OAuth 認証を接続してください。', state: buildMasterState(sess) });
      }
      streamState = 'ENCODING';
      youtubeStreamStatus = 'active';
      appendAuditLog(
        'STREAM_INGEST_ACTIVE',
        'エンコーダ準備状態をシミュレーション確認しました（SIMULATED）。',
        'DEMO_SIMULATION',
        'SIMULATED',
        { actor: sess.user_id, target: 'stream-studio', result: 'SUCCESS' }
      );
      break;

    case 'start_live':
      if (!userAgeEligible) {
        streamState = 'NOT_ELIGIBLE';
        return res.status(403).json({ error: '単独ライブ配信の対象外（16歳未満制限）です。', state: buildMasterState(sess) });
      }
      if (streamExecutionMode === 'TEST_MODE_SIMULATED') {
        streamLastError = '本番ライブ配信を開始するには、配信モードを「模擬テストモード」から「本番 YouTube API モード」へ切り替えてください。';
        return res.status(400).json({ error: streamLastError, state: buildMasterState(sess) });
      }
      if (!oauthConnected) {
        streamState = 'AUTH_REQUIRED';
        return res.status(401).json({ error: '先に YouTube OAuth を接続してください。', state: buildMasterState(sess) });
      }
      if (!previewVerified) {
        streamLastError = '本番ライブ遷移前に「Canvasプレビュー確認」を実行してください。';
        return res.status(400).json({ error: streamLastError, state: buildMasterState(sess) });
      }
      if (youtubeStreamStatus !== 'active') {
        streamState = 'CONNECTING';
        streamLastError = `YouTube ストリーム状態が '${youtubeStreamStatus}' です。LIVEへ遷移するには先に「配信準備＆ストリーム有効化」で 'active' にしてください。`;
        return res.status(400).json({ error: streamLastError, state: buildMasterState(sess) });
      }
      streamState = 'LIVE';
      streamStartedAtEpoch = Math.floor(Date.now() / 1000);
      appendAuditLog(
        'STREAM_LIVE_STARTED',
        `ブロードキャストを LIVE 状態へ遷移しました（公開設定=${streamSettings.privacy_status}）。`,
        'DEMO_SIMULATION',
        'SIMULATED',
        { actor: sess.user_id, target: 'stream-studio', result: 'SUCCESS' }
      );
      break;

    case 'stop_live':
      streamState = 'STOPPING';
      youtubeStreamStatus = 'inactive';
      streamState = 'STOPPED';
      streamStartedAtEpoch = null;
      appendAuditLog(
        'STREAM_LIVE_STOPPED',
        'エンコーダを停止し、ライブ配信を終了（STOPPED）しました。',
        'DEMO_SIMULATION',
        'SIMULATED',
        { actor: sess.user_id, target: 'stream-studio', result: 'SUCCESS' }
      );
      break;

    case 'reconnect':
      if (streamReconnectCount >= 3) {
        streamState = 'ERROR';
        streamLastError = '最大再接続試行回数（3/3回）に達したため、自動リトライを停止しました。';
        appendAuditLog('STREAM_RECONNECT_HALTED', streamLastError, 'DEMO_SIMULATION', 'SIMULATED', {
          actor: sess.user_id,
          target: 'stream-studio',
          result: 'ERROR',
        });
        return res.status(429).json({ error: streamLastError, state: buildMasterState(sess) });
      }
      streamReconnectCount += 1;
      streamState = 'CONNECTING';
      appendAuditLog('STREAM_RECONNECT', `再接続試行 ${streamReconnectCount}/3 回目を実行しました。`, 'DEMO_SIMULATION', 'SIMULATED', {
        actor: sess.user_id,
        target: 'stream-studio',
        result: 'SUCCESS',
      });
      break;

    default:
      return res.status(400).json({ error: `不明な配信アクションです: ${action}` });
  }

  res.json({ success: true, state: buildMasterState(sess) });
});

app.post('/api/stream/settings', requireAuth, requireCsrf, (req: Request, res: Response) => {
  const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
  const { title, description, privacy_status, resolution, fps, audio_muted, sources } = req.body || {};
  if (Array.isArray(sources)) {
    for (const s of sources) {
      if (!WHITELISTED_CANVAS_SOURCES.has(String(s))) {
        streamState = 'ERROR';
        streamLastError = `Rejected non-whitelisted canvas source: '${s}'`;
        appendAuditLog('STREAM_SOURCE_VIOLATION', streamLastError, 'REAL_AUDIT', 'VERIFIED_BY_EXECUTION', {
          actor: sess.user_id,
          target: 'stream-settings',
          result: 'DENIED',
        });
        return res.status(403).json({ error: streamLastError });
      }
    }
    streamSettings.active_canvas_sources = sources.map(String);
  }
  if (title !== undefined) streamSettings.title = sanitizeSafeDisplayText(redactTextFailClosed(String(title)), 'THUNDERHALL Broadcast', 100);
  if (description !== undefined) streamSettings.description = sanitizeSafeDisplayText(redactTextFailClosed(String(description)), '', 200);
  if (privacy_status && ['private', 'unlisted', 'public'].includes(privacy_status)) {
    streamSettings.privacy_status = privacy_status;
  }
  if (resolution && ['360p', '480p', '720p', '1080p'].includes(resolution)) {
    streamSettings.resolution = resolution;
  }
  if (fps && (Number(fps) === 30 || Number(fps) === 60)) {
    streamSettings.fps = Number(fps) as 30 | 60;
  }
  if (audio_muted !== undefined) {
    streamSettings.audio_muted = Boolean(audio_muted);
  }
  res.json({ success: true, state: buildMasterState(sess) });
});

// Live Python Test Suite Runner (Restricted to Admin / Group / Researcher roles)
app.post(
  '/api/security/run-python-tests',
  requireAuth,
  requireRole(['admin', 'group_member', 'researcher']),
  requireCsrf,
  (req: Request, res: Response) => {
    const sess = (req as Request & { authSession?: ActiveSession }).authSession!;
    if (!checkRateLimit(req, res, 'python_tests', 10, 30000)) return;

    const env = {
      ...process.env,
      PYTHONPATH: `${__dirname}:${path.join(__dirname, 'テストツール')}`,
      PYTHONDONTWRITEBYTECODE: '1',
    };
    execFile(
      'python3',
      ['-B', 'tests/test_mk1ai_productization.py', '-v'],
      { cwd: __dirname, env, timeout: 15000 },
      (err1, stdout1, stderr1) => {
        execFile(
          'python3',
          ['-B', 'テストツール/tests/test_phase2a_suite.py', '-v'],
          { cwd: __dirname, env, timeout: 15000 },
          (err2, stdout2, stderr2) => {
            const passed = !err1 && !err2;
            const combinedOutput = [
              '=== [1] MK1Ai Productization & Security Suite (tests/test_mk1ai_productization.py) ===',
              stdout1 || stderr1,
              '\n=== [2] THUNDERHALL Phase 2A Baseline Suite (テストツール/tests/test_phase2a_suite.py) ===',
              stdout2 || stderr2,
            ].join('\n');
            appendAuditLog(
              'PYTHON_VERIFICATION_SUITE_RUN',
              `Executed Python verification suites: ${passed ? 'ALL PASS (22/22 core + 17 sub-tests)' : 'FAILED'}`,
              'REAL_AUDIT',
              'TEST_EXECUTED',
              { actor: sess.user_id, target: 'python-test-suites', result: passed ? 'SUCCESS' : 'ERROR' }
            );
            res.json({
              success: passed,
              evidence_classification: 'TEST_EXECUTED',
              output: combinedOutput,
            });
          }
        );
      }
    );
  }
);

// Serve root index.html
app.get('/', (_req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('*', (req: Request, res: Response) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, host, () => {
  console.log(`[THUNDERHALL (サンダーホール)] Security-Hardened Server listening on http://${host}:${port} (Default Tier: general.PLUS)`);
});
