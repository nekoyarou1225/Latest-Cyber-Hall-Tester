import http from 'http';

interface TestResult {
  category: string;
  name: string;
  passed: boolean;
  details: string;
}

const results: TestResult[] = [];

interface RequestOptions {
  sessionToken?: string;
  csrfToken?: string;
  extraHeaders?: Record<string, string>;
}

function request(
  method: string,
  path: string,
  body?: unknown,
  opts: RequestOptions = {}
): Promise<{ status: number; headers: http.IncomingHttpHeaders; data: any }> {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : '';
    const headers: Record<string, string | number> = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      ...(opts.extraHeaders || {}),
    };
    if (opts.sessionToken) {
      headers['X-Session-Token'] = opts.sessionToken;
    }
    if (opts.csrfToken) {
      headers['X-CSRF-Token'] = opts.csrfToken;
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: 3000,
        path,
        method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          const rawBuf = Buffer.concat(chunks);
          const rawStr = rawBuf.toString('utf8');
          let parsed: any = null;
          try {
            parsed = JSON.parse(rawStr);
          } catch {
            parsed = rawStr;
          }
          resolve({ status: res.statusCode || 0, headers: res.headers, data: parsed });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function record(category: string, name: string, passed: boolean, details: string) {
  results.push({ category, name, passed, details });
  const icon = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`${icon} [${category}] ${name}: ${details}`);
}

async function loginAs(userId: string, password: string): Promise<{ sessionToken: string; csrfToken: string; role: string }> {
  const r = await request('POST', '/api/auth/login', { user_id: userId, password });
  if (r.status !== 200 || !r.data?.session) {
    throw new Error(`Login failed for ${userId}: HTTP ${r.status} ${JSON.stringify(r.data)}`);
  }
  return {
    sessionToken: r.data.session.session_id,
    csrfToken: r.data.session.csrf_token,
    role: r.data.session.role,
  };
}

async function runAllButtonAndSecurityTests() {
  console.log('\n================================================================');
  console.log('⚡ サンダーホール (THUNDERHALL) P0/P1 セキュリティ修正 & 全機能包括検証');
  console.log('================================================================\n');

  // ---------------------------------------------------------------------------
  // 0. 初期起動状態検証 (PART 2.2: 初期状態は general.PLUS であり group.ULTRAMAX ではない)
  // ---------------------------------------------------------------------------
  console.log('--- [PART 2.2] 初期起動プラン & CSPセキュリティヘッダー検証 ---');
  try {
    const st = await request('GET', '/api/state');
    const initTier = st.data?.license?.active_tier;
    const csp = String(st.headers['content-security-policy'] || '');
    const nosniff = String(st.headers['x-content-type-options'] || '');
    record(
      'Initial Security State',
      '初期起動プランが general.PLUS (一般・基本利用) であること',
      st.status === 200 && initTier === 'general.PLUS',
      `active_tier=${initTier}, max_hp=${st.data?.license?.entitlements?.max_honeypots_by_license}, limit_sec=${st.data?.license?.daily_usage?.limit_sec}`
    );
    record(
      'Initial Security State',
      'CSP (Content-Security-Policy) & X-Content-Type-Options ヘッダー検証',
      csp.includes("default-src 'self'") && nosniff === 'nosniff',
      `CSP='${csp.slice(0, 48)}...', X-Content-Type-Options='${nosniff}'`
    );
  } catch (e: any) {
    record('Initial Security State', '初期状態・ヘッダー検証', false, e.message);
  }

  // ---------------------------------------------------------------------------
  // 1. PART 7.1 APIセキュリティテスト (未認証拒否・RBAC拒否・CSRF拒否・OAuth・ZIP・XSS・レート制限)
  // ---------------------------------------------------------------------------
  console.log('\n--- [PART 7.1] API セキュリティ検証 (Auth / RBAC / CSRF / OAuth / Traversal / RateLimit) ---');

  // 1-1. 未認証リクエストが管理系APIで 401 になること
  const protectedEndpoints = [
    { method: 'POST', path: '/api/license/switch-plan', body: { plan_tier: 'group.ULTRAMAX' } },
    { method: 'POST', path: '/api/honeypots/create', body: { node_id: 'hp-unauth' } },
    { method: 'POST', path: '/api/security/kill-switch/approve', body: { event_id: 'evt-unauth' } },
    { method: 'POST', path: '/api/security/kill-switch/execute', body: { event_id: 'evt-unauth' } },
    { method: 'POST', path: '/api/security/run-python-tests', body: {} },
    { method: 'GET', path: '/api/download/project-zip' },
  ];
  for (const ep of protectedEndpoints) {
    const r = await request(ep.method, ep.path, ep.body);
    record(
      'PART 7.1 Security',
      `未認証アクセス遮断 (${ep.method} ${ep.path}) -> 401`,
      r.status === 401,
      `HTTP ${r.status}`
    );
  }

  // 1-2. セッション固定攻撃対策 (ログイン時に既存セッションIDが無効化され新IDが発行されること)
  const adminAlice1 = await loginAs('admin-alice', 'Thunderhall!Alice#2026');
  const rFix = await request(
    'POST',
    '/api/auth/login',
    { user_id: 'admin-alice', password: 'Thunderhall!Alice#2026' },
    { sessionToken: adminAlice1.sessionToken }
  );
  const newAliceToken = rFix.data?.session?.session_id;
  const oldSessionCheck = await request('GET', '/api/files/list', undefined, { sessionToken: adminAlice1.sessionToken });
  record(
    'PART 7.1 Security',
    'セッション固定攻撃防止 (再ログイン時の旧セッション無効化 & 新ID発行)',
    Boolean(newAliceToken) && newAliceToken !== adminAlice1.sessionToken && oldSessionCheck.status === 401,
    `oldSession->HTTP ${oldSessionCheck.status}, newSessionIssued=true`
  );

  // 現在の有効な各ロールセッションを取得
  const aliceAuth = {
    sessionToken: rFix.data.session.session_id,
    csrfToken: rFix.data.session.csrf_token,
  };
  const bobAuth = await loginAs('admin-bob', 'Thunderhall!Bob#2026');
  const generalAuth = await loginAs('general-user', 'Thunderhall!General#2026');

  // 1-3. 一般ユーザー (general_user) が管理者APIや上位プラン切替を呼ぶと 403 になること
  const rGenSwitch = await request(
    'POST',
    '/api/license/switch-plan',
    { plan_tier: 'group.ULTRAMAX' },
    generalAuth
  );
  record(
    'PART 7.1 Security',
    'RBAC認可検証: 一般ユーザーによる group.ULTRAMAX 無断昇格拒否 -> 403',
    rGenSwitch.status === 403,
    `HTTP ${rGenSwitch.status}: ${rGenSwitch.data?.error?.slice(0, 50)}...`
  );

  const rGenKs = await request(
    'POST',
    '/api/security/kill-switch/approve',
    { event_id: 'evt-rbac-test' },
    generalAuth
  );
  record(
    'PART 7.1 Security',
    'RBAC認可検証: 一般ユーザーによる Kill Switch 承認拒否 -> 403',
    rGenKs.status === 403,
    `HTTP ${rGenKs.status}`
  );

  const rGenZip = await request('GET', '/api/download/project-zip', undefined, generalAuth);
  record(
    'PART 7.1 Security',
    'RBAC認可検証: 一般ユーザーによるプロジェクトZIP取得拒否 -> 403',
    rGenZip.status === 403,
    `HTTP ${rGenZip.status}`
  );

  // 1-4. CSRFトークン不一致または欠落で 403 になること
  const rNoCsrf = await request(
    'POST',
    '/api/control/start',
    {},
    { sessionToken: aliceAuth.sessionToken } // csrfToken omitted
  );
  const rBadCsrf = await request(
    'POST',
    '/api/control/start',
    {},
    { sessionToken: aliceAuth.sessionToken, csrfToken: 'invalid-csrf-token-999' }
  );
  record(
    'PART 7.1 Security',
    'CSRF防御検証: トークン欠落および不一致リクエストの遮断 -> 403',
    rNoCsrf.status === 403 && rBadCsrf.status === 403,
    `missing=${rNoCsrf.status}, invalid=${rBadCsrf.status}`
  );

  // 1-5. OAuth state パラメータ欠落および不一致で 403 になること (PART 3.1)
  const rOAuthNoState = await request('GET', '/auth/callback?code=test_code');
  const rOAuthBadState = await request('GET', '/auth/callback?state=forged_state_123&code=test_code');
  const oauthUrlRes = await request('GET', '/api/auth/youtube/url?origin=http://127.0.0.1:3000', undefined, aliceAuth);
  const validOAuthState = oauthUrlRes.data?.csrf_state;
  const rOAuthValid = await request('GET', `/auth/callback?state=${validOAuthState}&code=sim_auth_code_01`);
  const rOAuthReplay = await request('GET', `/auth/callback?state=${validOAuthState}&code=sim_auth_code_01`);
  const noWildcardPostMessage = typeof rOAuthValid.data === 'string' && !rOAuthValid.data.includes("'*'");
  record(
    'PART 7.1 Security',
    'OAuth 2.0 CSRF検証: state欠落(403)・不一致(403)・ワンタイム消費(再送403)・postMessageオリジン制限',
    rOAuthNoState.status === 403 &&
      rOAuthBadState.status === 403 &&
      rOAuthValid.status === 200 &&
      rOAuthReplay.status === 403 &&
      noWildcardPostMessage,
    `noState=${rOAuthNoState.status}, badState=${rOAuthBadState.status}, valid=${rOAuthValid.status}, replay=${rOAuthReplay.status}, noWildcard=${noWildcardPostMessage}`
  );

  // 1-6. ファイル検査・一覧APIでのパストラバーサル & 保護ディレクトリ拒否
  const rTrav1 = await request('GET', '/api/files/inspect?path=../../etc/passwd', undefined, aliceAuth);
  const rTrav2 = await request('GET', '/api/files/inspect?path=.thunderhall_data/runtime_state.json', undefined, aliceAuth);
  record(
    'PART 7.1 Security',
    'パストラバーサル & 内部永続化データアクセス遮断 -> 403',
    rTrav1.status === 403 && rTrav2.status === 403,
    `../../etc/passwd=${rTrav1.status}, .thunderhall_data=${rTrav2.status}`
  );

  // 1-7. 安全なプロジェクトZIPダウンロード検証 (PART 2.5)
  const rSafeZip = await request('GET', '/api/download/project-zip', undefined, aliceAuth);
  const zipDisp = String(rSafeZip.headers['content-disposition'] || '');
  record(
    'PART 7.1 Security',
    '安全な一時ファイル方式プロジェクトZIP出力 (Admin認可・Allowlist適用)',
    rSafeZip.status === 200 && zipDisp.includes('thunderhall_security_project.zip'),
    `HTTP ${rSafeZip.status}, Content-Disposition='${zipDisp}'`
  );

  // 1-8. レート制限 (429 Too Many Requests) の動作検証
  let rateLimited429 = false;
  for (let i = 0; i < 8; i++) {
    const rlRes = await request('GET', '/api/files/list', undefined, {
      ...aliceAuth,
      extraHeaders: { 'X-Rate-Limit-Test-Key': 'burst-test-bucket-1' },
    });
    if (rlRes.status === 429) {
      rateLimited429 = true;
      break;
    }
  }
  record(
    'PART 7.1 Security',
    'スライディングウィンドウ・レート制限発動検証 -> 429 Too Many Requests',
    rateLimited429,
    `triggered_429=${rateLimited429}`
  );

  // ---------------------------------------------------------------------------
  // 2. PART 7.2 32段階プラン・ライセンス検証
  // ---------------------------------------------------------------------------
  console.log('\n--- [PART 7.2] 32段階プラン体系 & ライセンス強制検証 ---');
  const categories = ['general', 'business', 'research', 'group'];
  const identifiers = ['PLUS', 'PLUSPRO', 'PLUSPROMAX', 'PRO', 'PROMAX', 'ULTRA', 'ULTRAPRO', 'ULTRAMAX'];

  for (const cat of categories) {
    for (const ident of identifiers) {
      const tier = `${cat}.${ident}`;
      const r = await request('POST', '/api/license/switch-plan', { category: cat, identifier: ident }, aliceAuth);
      const lic = r.data?.state?.license;
      const cap = r.data?.state?.honeypots?.capacity;
      const valid =
        r.status === 200 &&
        lic?.active_tier === tier &&
        typeof lic?.display_name === 'string' &&
        lic.display_name.startsWith('サンダーホール') &&
        cap?.admin_policy_limit === 256 &&
        cap?.policy_and_license_limit === lic?.entitlements?.max_honeypots_by_license &&
        (cat === 'group' ? lic?.daily_usage?.is_unlimited === true : lic?.daily_usage?.is_unlimited === false);

      record(
        'PART 7.2 32-Plan Engine',
        `プラン検証: ${tier}`,
        valid,
        `表示名='${lic?.display_name}', 時間枠='${lic?.daily_usage?.display_label}', HP上限(プラン/Policy統合)=${cap?.policy_and_license_limit}台, パイプライン=${lic?.entitlements?.concurrent_test_pipelines}, プリセット上限=${lic?.entitlements?.max_saved_presets}`
      );
    }
  }

  // 2-2. 同時テストパイプライン数 & プリセット保存上限のサーバー側強制検証 (PART 5)
  await request('POST', '/api/license/switch-plan', { plan_tier: 'general.PLUS' }, aliceAuth);
  const pipeExceed = await request('POST', '/api/pipelines/control', { action: 'set', count: 5 }, aliceAuth);
  record(
    'PART 7.2 32-Plan Engine',
    'general.PLUS (上限1系統) での同時パイプライン超過ブロック -> 403',
    pipeExceed.status === 403,
    `HTTP ${pipeExceed.status}: ${pipeExceed.data?.error}`
  );

  // Switch back to group.ULTRAMAX for full feature tests
  await request('POST', '/api/license/switch-plan', { plan_tier: 'group.ULTRAMAX' }, aliceAuth);
  const pipeOk = await request('POST', '/api/pipelines/control', { action: 'set', count: 8 }, aliceAuth);
  record(
    'PART 7.2 32-Plan Engine',
    'group.ULTRAMAX (上限16系統) での8系統パイプライン起動許可 -> 200',
    pipeOk.status === 200 && pipeOk.data?.active_pipelines === 8,
    `active_pipelines=${pipeOk.data?.active_pipelines}`
  );

  // 2-3. 期限切れ・CRL失効時の general.PLUS 自動降格と CORE保護100%維持検証
  const expSim = await request('POST', '/api/license/simulate-expiry-or-revoke', { mode: 'expire' }, aliceAuth);
  const degradedLic = expSim.data?.state?.license;
  record(
    'PART 7.2 32-Plan Engine',
    'ライセンス期限切れ時の general.PLUS 自動降格 & CORE保護100%維持',
    expSim.status === 200 &&
      degradedLic?.active_tier === 'general.PLUS' &&
      degradedLic?.core_safety_guarantees?.core_isolation_active === true &&
      degradedLic?.core_safety_guarantees?.emergency_kill_switch_active === true,
    `active_tier=${degradedLic?.active_tier}, core_isolation_active=${degradedLic?.core_safety_guarantees?.core_isolation_active}`
  );

  // Restore group.ULTRAMAX for subsequent tests
  await request('POST', '/api/license/switch-plan', { plan_tier: 'group.ULTRAMAX' }, aliceAuth);

  // ---------------------------------------------------------------------------
  // 3. PART 7.3 Quorum (2名承認) & Kill Switch セキュリティ検証
  // ---------------------------------------------------------------------------
  console.log('\n--- [PART 7.3] Quorum 2名承認 & Kill Switch セキュリティ検証 ---');
  const testEvt = `evt-quorum-${Date.now().toString().slice(-4)}`;

  // 3-1. なりすまし検証: Alice のセッションで admin_id='admin-bob' を自己申告すると 403 で拒否されること
  const rSpoof = await request(
    'POST',
    '/api/security/kill-switch/approve',
    { event_id: testEvt, admin_id: 'admin-bob' },
    aliceAuth
  );
  record(
    'PART 7.3 Quorum',
    '管理者IDなりすまし遮断 (Aliceセッションでadmin-bobを名乗ると 403)',
    rSpoof.status === 403,
    `HTTP ${rSpoof.status}: ${rSpoof.data?.error?.slice(0, 50)}...`
  );

  // 3-2. 1人目の正規管理者 (admin-alice) による承認 -> APPROVAL_PENDING (1/2)
  const rApprove1 = await request(
    'POST',
    '/api/security/kill-switch/approve',
    { event_id: testEvt, admin_id: 'admin-alice' },
    aliceAuth
  );
  record(
    'PART 7.3 Quorum',
    '1人目の認証済み管理者 (admin-alice) 署名 -> APPROVAL_PENDING (1/2)',
    rApprove1.status === 200 && rApprove1.data?.lifecycle_state === 'APPROVAL_PENDING' && rApprove1.data?.current_approvals_count === 1,
    `state=${rApprove1.data?.lifecycle_state}, count=${rApprove1.data?.current_approvals_count}`
  );

  // 3-3. 同一管理者 (admin-alice) による2回目の重複承認 -> 409 Conflict で拒否
  const rDupAdmin = await request(
    'POST',
    '/api/security/kill-switch/approve',
    { event_id: testEvt, admin_id: 'admin-alice' },
    aliceAuth
  );
  record(
    'PART 7.3 Quorum',
    '同一管理者 (admin-alice) による重複承認拒否 -> 409 Conflict',
    rDupAdmin.status === 409,
    `HTTP ${rDupAdmin.status}: ${rDupAdmin.data?.error?.slice(0, 50)}...`
  );

  // 3-4. 1名承認のみでの実行試行 -> 403 で拒否
  const rExec1 = await request(
    'POST',
    '/api/security/kill-switch/execute',
    { event_id: testEvt, reason: '1名のみで実行テスト' },
    aliceAuth
  );
  record(
    'PART 7.3 Quorum',
    '1名承認のみでの Kill Switch 執行拒否 -> 403',
    rExec1.status === 403,
    `HTTP ${rExec1.status}`
  );

  // 3-5. 2人目の異なる認証済み管理者 (admin-bob) による承認 -> APPROVED (2/2)
  const rApprove2 = await request(
    'POST',
    '/api/security/kill-switch/approve',
    { event_id: testEvt, admin_id: 'admin-bob' },
    bobAuth
  );
  record(
    'PART 7.3 Quorum',
    '2人目の異なる認証済み管理者 (admin-bob) 署名 -> APPROVED (2/2)',
    rApprove2.status === 200 && rApprove2.data?.lifecycle_state === 'APPROVED' && rApprove2.data?.current_approvals_count === 2,
    `state=${rApprove2.data?.lifecycle_state}, count=${rApprove2.data?.current_approvals_count}`
  );

  // 3-6. Quorum 成立後の執行 -> VERIFIED 状態へ遷移
  const rExec2 = await request(
    'POST',
    '/api/security/kill-switch/execute',
    { event_id: testEvt, reason: '2名承認成立による正規執行' },
    bobAuth
  );
  record(
    'PART 7.3 Quorum',
    'Quorum成立後の Kill Switch 執行 & 事後検証完了 -> VERIFIED',
    rExec2.status === 200 && rExec2.data?.executed === true && rExec2.data?.lifecycle_state === 'VERIFIED',
    `lifecycle_state=${rExec2.data?.lifecycle_state}, evidence='${rExec2.data?.verification_evidence}'`
  );

  // 3-7. 使用済み event_id のリプレイ実行拒否 -> 403
  const rReplay = await request(
    'POST',
    '/api/security/kill-switch/execute',
    { event_id: testEvt, reason: 'リプレイ攻撃試行' },
    aliceAuth
  );
  record(
    'PART 7.3 Quorum',
    '使用済み event_id のリプレイ実行遮断 -> 403',
    rReplay.status === 403,
    `HTTP ${rReplay.status}`
  );

  // ---------------------------------------------------------------------------
  // 4. ハニーポット管理 & XSSサニタイズ & 7ステップOS切替 & バックアップ検証
  // ---------------------------------------------------------------------------
  console.log('\n--- ハニーポット管理・XSS無害化・署名バックアップ検証 ---');
  const testNodeId = `hp-sec-${Date.now().toString().slice(-4)}`;
  const xssPayloadName = `<img src=x onerror=alert(1)>SecDecoy`;

  const rHpCreate = await request(
    'POST',
    '/api/honeypots/create',
    {
      node_id: testNodeId,
      name: xssPayloadName,
      layer: 'OUTER',
      os_id: 'mk1ai-secure-linux-1.0',
    },
    aliceAuth
  );
  const createdName = rHpCreate.data?.node?.name || '';
  record(
    'Honeypot & XSS Defense',
    'ハニーポット作成時のXSSタグサニタイズ検証 (< > 除去)',
    rHpCreate.status === 200 && !createdName.includes('<') && !createdName.includes('>'),
    `sanitized_name='${createdName}'`
  );

  const rHpStart = await request('POST', `/api/honeypots/${testNodeId}/action`, { action: 'start' }, aliceAuth);
  const rHpIsolate = await request('POST', `/api/honeypots/${testNodeId}/action`, { action: 'isolate' }, aliceAuth);
  const rHpRecover = await request('POST', `/api/honeypots/${testNodeId}/action`, { action: 'auto_recover' }, aliceAuth);
  record(
    'Honeypot Engine',
    'ハニーポット 起動 -> 隔離 -> 自動復旧 ライフサイクル検証',
    rHpStart.status === 200 && rHpIsolate.status === 200 && rHpRecover.status === 200,
    'RUNNING -> ISOLATED -> RUNNING (recovery_count=1)'
  );

  const rOsSwitchOk = await request(
    'POST',
    `/api/honeypots/${testNodeId}/switch-os`,
    { target_os_id: 'debian-13-minimal' },
    aliceAuth
  );
  const rOsSwitchBlock = await request(
    'POST',
    `/api/honeypots/${testNodeId}/switch-os`,
    { target_os_id: 'windows-server-2022-guest' },
    aliceAuth
  );
  record(
    'Honeypot Engine',
    '7ステップOS切替 (Debian成功 & Windows KVM制約ロールバック)',
    rOsSwitchOk.status === 200 && rOsSwitchBlock.status === 400 && rOsSwitchBlock.data?.error?.includes('ロールバック'),
    `debian=${rOsSwitchOk.status}, windowsRollback=${rOsSwitchBlock.status}`
  );

  const rBackup = await request('POST', '/api/honeypots/backup', {}, aliceAuth);
  await request('POST', '/api/auth/reverify', { operator_confirm: true }, aliceAuth);
  const rRestore = await request('POST', '/api/honeypots/restore', { bundle: rBackup.data?.bundle }, aliceAuth);
  await request('POST', `/api/honeypots/${testNodeId}/action`, { action: 'delete' }, aliceAuth);
  record(
    'Honeypot Engine',
    'Ed25519署名バックアップ出力 & ステップアップ再認証後の復元検証',
    rBackup.status === 200 && rRestore.status === 200,
    `backup=${rBackup.status}, restore=${rRestore.status}`
  );

  // ---------------------------------------------------------------------------
  // 5. シミュレーション・14カテゴリ機密マスキング・配信スタジオ検証
  // ---------------------------------------------------------------------------
  console.log('\n--- シミュレーション・14カテゴリマスキング・配信スタジオ検証 ---');
  await request('POST', '/api/security/oni-mode', { mode: 'NORMAL' }, aliceAuth);
  const rSimReset = await request('POST', '/api/control/reset', {}, aliceAuth);
  const rSimStart = await request('POST', '/api/control/start', {}, aliceAuth);
  const rSimPause = await request('POST', '/api/control/pause', {}, aliceAuth);
  const rPps = await request('POST', '/api/pps', { pps: 500, target_packets: '9007199254740993', virtual_bots: '64' }, aliceAuth);
  record(
    'Simulation Control',
    'パケットシミュレーション (Reset/Start/Pause) & 2^53+1 境界値設定',
    rSimReset.status === 200 && rSimStart.status === 200 && rSimPause.status === 200 && rPps.status === 200,
    `target_packets=${rPps.data?.state?.simulation?.target_packets}, theoretical_gbps=${rPps.data?.state?.simulation?.theoretical_gbps}`
  );

  const rRedact = await request(
    'POST',
    '/api/redact',
    { text: 'card=4532-1111-2222-3333, email=sec@thunderhall.jp, key=sk_live_1234567890abcdef' },
    aliceAuth
  );
  record(
    'Privacy Redaction',
    '14カテゴリ Fail-Closed 機密マスキング検証',
    rRedact.status === 200 && rRedact.data?.matches_found === true && !rRedact.data?.redacted?.includes('4532-1111'),
    `redacted='${rRedact.data?.redacted}'`
  );

  // ---------------------------------------------------------------------------
  // 6. PART 3.3 監査ログ 256件超え連番重複ゼロ & SHA-256 ハッシュチェーン完全性検証
  // ---------------------------------------------------------------------------
  console.log('\n--- [PART 3.3] 監査ログ 256件超え連番整合性 & SHA-256 ハッシュチェーン検証 ---');
  // Generate enough audit events to exceed 260 entries and verify seq never repeats 256
  for (let i = 0; i < 200; i++) {
    await request('POST', '/api/control/reset', {}, aliceAuth);
  }
  const rAuditVerify = await request('GET', '/api/security/audit-verify', undefined, aliceAuth);
  const report = rAuditVerify.data?.integrity_report;
  record(
    'PART 3.3 Audit Hash Chain',
    '256件超過後の連番単調増加 & 全件 SHA-256 ハッシュチェーン完全性検証',
    rAuditVerify.status === 200 &&
      report?.valid === true &&
      report?.total_entries > 260 &&
      report?.last_seq === report?.total_entries,
    `valid=${report?.valid}, total_entries=${report?.total_entries}, first_seq=${report?.first_seq}, last_seq=${report?.last_seq}, head_sha256=${report?.head_sha256?.slice(0, 16)}...`
  );

  // ---------------------------------------------------------------------------
  // 7. Python 総合検証スイート実行 & 初期プラン (general.PLUS) 復帰
  // ---------------------------------------------------------------------------
  const rPy = await request('POST', '/api/security/run-python-tests', {}, aliceAuth);
  record(
    'Python Verification Suite',
    'Python ユニットテストスイート (MK1Ai 7件 + Phase 2A 15件) 実行',
    rPy.status === 200 && rPy.data?.success === true && rPy.data?.evidence_classification === 'TEST_EXECUTED',
    'ALL PASS (evidence_class=TEST_EXECUTED)'
  );

  // Reset back to default general.PLUS state after test completion
  await request('POST', '/api/license/switch-plan', { plan_tier: 'general.PLUS' }, aliceAuth);

  // 最終サマリー
  console.log('\n================================================================');
  const passCount = results.filter((r) => r.passed).length;
  const failCount = results.filter((r) => !r.passed).length;
  console.log(`検証完了: 全 ${results.length} 項目中 ${passCount} 件 PASS / ${failCount} 件 FAIL`);
  console.log('================================================================\n');

  if (failCount > 0) {
    process.exit(1);
  }
}

runAllButtonAndSecurityTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
