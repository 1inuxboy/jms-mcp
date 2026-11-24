import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeConfig, resolveAccount } from '../src/config.js';
import { parsePinentryOutput, parseOsascriptOutput, parsePinentryPassword, parseOsascriptPassword, headlessReason } from '../src/prompt.js';
import { loginDescription, tokenUsername } from '../src/session.js';
import { ASSET_ID, FP, RAW, makePool } from './helpers.js';

// ---------- config ----------
test('配置规范化：UUID 小写、默认账号取第一个、指纹去前缀、默认 24 小时', () => {
  const raw = structuredClone(RAW);
  delete raw.ttlHours;
  const c = normalizeConfig(raw);
  assert.equal(c.assets['web-1'].id, ASSET_ID);
  assert.equal(c.assets['web-1'].defaultAccount, 'ops');
  assert.deepEqual(c.koko.hostKeySha256, [FP]);
  assert.equal(c.ttlMs, 24 * 3600_000);
  assert.equal(c.jumpserver.baseUrl, 'https://koko.test');
});

test('配置：资产 id 可省略、不再需要私钥，写了就必须是 UUID', () => {
  const noId = structuredClone(RAW);
  delete noId.assets['web-1'].id;
  assert.equal(normalizeConfig(noId).assets['web-1'].id, null);
  const bad = structuredClone(RAW);
  bad.assets['web-1'].id = 'web-1';
  assert.throws(() => normalizeConfig(bad), /UUID/);
});

test('配置：jumpserver.baseUrl 可覆盖，格式不对报错', () => {
  const ok = structuredClone(RAW);
  ok.jumpserver = { baseUrl: 'https://js.example.com:8443/' };
  assert.equal(normalizeConfig(ok).jumpserver.baseUrl, 'https://js.example.com:8443');
  const bad = structuredClone(RAW);
  bad.jumpserver = { baseUrl: 'js.example.com' };
  assert.throws(() => normalizeConfig(bad), /baseUrl/);
});

test('配置：jumpserver.baseUrl 拒绝明文 HTTP（密码和动态码经此提交）', () => {
  const bad = structuredClone(RAW);
  bad.jumpserver = { baseUrl: 'http://js.example.com' };
  assert.throws(() => normalizeConfig(bad), /HTTPS/);
});

test('配置校验：默认账号是特权账号报错', () => {
  const bad = structuredClone(RAW);
  bad.assets['web-1'].defaultAccount = 'admin';
  assert.throws(() => normalizeConfig(bad), /不能是特权账号/);
});

test('账号解析：默认非特权，特权需显式 + privileged', () => {
  const a = normalizeConfig(RAW).assets['web-1'];
  assert.equal(resolveAccount(a, undefined), 'ops');
  assert.throws(() => resolveAccount(a, 'admin'), /特权账号/);
  assert.equal(resolveAccount(a, 'admin', true), 'admin');
  assert.throws(() => resolveAccount(a, 'root', true), /未配置账号/);
});

// ---------- prompt ----------
test('弹窗输出解析：OTP 只接受 6-8 位数字', () => {
  assert.equal(parsePinentryOutput('OK Pleased\r\nD 123456\r\nOK\r\n'), '123456');
  assert.equal(parsePinentryOutput('OK\nERR 83886179 Operation cancelled\n'), null);
  assert.equal(parseOsascriptOutput('654321\n'), '654321');
  assert.equal(parseOsascriptOutput('abc\n'), null);
  assert.equal(parseOsascriptOutput(''), null);
});

test('弹窗输出解析：密码保留原样，仅还原 Assuan 的 % 与换行编码', () => {
  assert.equal(parsePinentryPassword('OK\r\nD pa%25ss word\r\nOK\r\n'), 'pa%ss word');
  assert.equal(parsePinentryPassword('ERR 83886179 Operation cancelled\n'), null);
  assert.equal(parseOsascriptPassword(' 密码 with space \n'), ' 密码 with space ');
  assert.equal(parseOsascriptPassword('\n'), null);
  assert.equal(parseOsascriptPassword(''), null);
});

test('SSH 远程会话中拒绝弹窗', () => {
  assert.match(headlessReason({ SSH_CONNECTION: '1 2 3 4' }, 'darwin'), /SSH/);
  assert.equal(headlessReason({}, 'darwin'), null);
  assert.equal(headlessReason({}, 'win32'), null);
  assert.match(headlessReason({}, 'linux'), /linux/);
});

// ---------- 登录态与令牌 ----------
test('KoKo 令牌用户名格式', () => {
  assert.equal(tokenUsername('abc-123'), 'JMS-abc-123');
});

test('登录只弹一次密码和 OTP，之后每条命令各用一次性令牌，不再弹窗', async () => {
  const { pool, config, clients, api, prompts, passwords } = makePool();
  const asset = config.assets['web-1'];
  const r1 = await pool.run(asset, 'ops', 'id', 1000);
  const r2 = await pool.run(asset, 'ops', 'uptime', 1000);
  assert.equal(r1.exitCode, 0);
  assert.equal(r2.stdout, 'ran:uptime\n');
  assert.equal(passwords(), 1);
  assert.equal(prompts(), 1);
  assert.equal(api.logins, 1);
  assert.equal(api.tokens.length, 2);
  assert.equal(api.assetLookups, 0); // 配置里写了 id，不用再查
  assert.equal(api.accountLookups, 1); // 账号别名只查一次
  assert.deepEqual(api.tokens.map((t) => t.alias), ['alias-ops', 'alias-ops']);
  assert.equal(clients.length, 2); // 每条命令一条短连接
  assert.equal(clients[0].opts.username, 'JMS-tok-1');
  assert.equal(clients[1].opts.username, 'JMS-tok-2');
  assert.equal(clients[0].opts.password, 'secret-1');
  assert.ok(clients.every((c) => c.ended)); // 执行完即断开
  assert.equal(r1.sessionExpiresAt, pool.sessions.get('login').expiresAt);
  pool.closeAll();
});

test('密码只用于登录，不被登录态保留', async () => {
  const { pool, config, api } = makePool();
  await pool.run(config.assets['web-1'], 'ops', 'id', 1000);
  assert.equal(api.lastLogin.passwordLength, 'pw-secret-1'.length);
  assert.ok(!JSON.stringify([...pool.sessions.values()].map(({ timer, ...rest }) => rest)).includes('pw-secret-1'));
  pool.closeAll();
});

test('并发调用共用一次登录', async () => {
  const { pool, config, api, prompts, passwords } = makePool();
  const asset = config.assets['web-1'];
  await Promise.all([pool.run(asset, 'ops', 'a', 1000), pool.run(asset, 'ops', 'b', 1000)]);
  assert.equal(api.logins, 1);
  assert.equal(passwords(), 1);
  assert.equal(prompts(), 1);
  pool.closeAll();
});

test('换账号不再要 MFA，各自用对应账号别名申请令牌', async () => {
  const { pool, config, api, prompts } = makePool();
  const asset = config.assets['web-1'];
  await pool.run(asset, 'ops', 'id', 1000);
  await pool.run(asset, 'admin', 'id', 1000);
  assert.equal(prompts(), 1);
  assert.deepEqual(api.tokens.map((t) => t.alias), ['alias-ops', 'alias-admin']);
  pool.closeAll();
});

test('资产没写 id 时按名称查，查不到给出可读原因', async () => {
  const raw = structuredClone(RAW);
  delete raw.assets['web-1'].id;
  const { pool, config, api } = makePool({}, {}, raw);
  await pool.run(config.assets['web-1'], 'ops', 'id', 1000);
  assert.equal(api.assetLookups, 1);
  assert.equal(api.tokens[0].assetId, ASSET_ID);

  const ghost = structuredClone(RAW);
  ghost.assets['ghost-1'] = { accounts: ['ops'] };
  const g = makePool({}, {}, ghost);
  await assert.rejects(g.pool.run(g.config.assets['ghost-1'], 'ops', 'id', 1000), /没有授权给你的资产 ghost-1/);
  pool.closeAll();
  g.pool.closeAll();
});

test('JumpServer 没授权这个账号时给出已授权列表', async () => {
  const { pool, config } = makePool();
  await assert.rejects(pool.run(config.assets['web-1'], 'ghost', 'id', 1000), /没有授权给你的账号 ghost，已授权: ops, admin/);
  pool.closeAll();
});

test('取消密码时不发起登录，也不留下登录态', async () => {
  const { pool, config, api, prompts } = makePool({ password: null });
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /未输入密码/);
  assert.equal(api.logins, 0);
  assert.equal(prompts(), 0);
  assert.equal(pool.sessions.size, 0);
});

test('取消 OTP 时登录失败且不缓存', async () => {
  const { pool, config } = makePool({ otp: null });
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /未输入 OTP/);
  assert.equal(pool.sessions.size, 0);
  assert.equal(pool.pending.size, 0);
});

test('OTP 被拒绝时给出可读原因，且不缓存登录态', async () => {
  const { pool, config } = makePool({ otp: '000000' });
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /MFA 验证失败/);
  assert.equal(pool.sessions.size, 0);
});

test('主机指纹不符时拒绝连接', async () => {
  const { pool, config } = makePool({ hostKey: Buffer.from('evil') });
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /指纹/);
  pool.closeAll();
});

test('KoKo 仍要求 MFA 时不回答，直接报错', async () => {
  const { pool, config, clients } = makePool({ mfa: true });
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /仍要求 MFA/);
  assert.deepEqual(clients[0].answers, ['']); // 只给空答案让握手结束，不提交任何动态码
  assert.equal(clients[0].ended, true);
  pool.closeAll();
});

test('到达有效期后再执行，重新登录', async () => {
  let now = 1_000_000;
  const { pool, config, api, prompts } = makePool({}, { now: () => now });
  const asset = config.assets['web-1'];
  await pool.run(asset, 'ops', 'id', 1000);
  now += config.ttlMs + 1;
  await pool.run(asset, 'ops', 'id', 1000);
  assert.equal(api.logins, 2);
  assert.equal(prompts(), 2);
  pool.closeAll();
});

test('TTL 定时器到点自动结束登录态', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const { pool, config } = makePool();
    await pool.ensureLogin();
    assert.equal(pool.sessions.size, 1);
    mock.timers.tick(config.ttlMs);
    assert.equal(pool.sessions.size, 0);
  } finally {
    mock.timers.reset();
  }
});

test('有效期取本地上限与服务端过期时间中较早者', async () => {
  const now = 1_000_000;
  const { pool, config } = makePool({ loginExpiresAt: now + 10 * 60_000 }, { now: () => now });
  await pool.ensureLogin();
  assert.equal(pool.status()[0].remainingMinutes, 10);
  assert.ok(config.ttlMs > 10 * 60_000);
  pool.closeAll();
});

test('登录态被服务端判失效时重新登录一次再重试', async () => {
  const { pool, config, api, prompts, passwords } = makePool({ unauthorizedOnce: true });
  const r = await pool.run(config.assets['web-1'], 'ops', 'id', 1000);
  assert.equal(r.exitCode, 0);
  assert.equal(api.logins, 2);
  assert.equal(passwords(), 2);
  assert.equal(prompts(), 2);
  pool.closeAll();
});

test('账号别名失效时刷新一次资产信息，仍失败则报错', async () => {
  const { JmsApiError } = await import('../src/jumpserver.js');
  const { pool, config, api } = makePool({ tokenError: new JmsApiError('申请连接令牌失败: Account not found', { code: 'perm_account_invalid', status: 400 }) });
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /Account not found/);
  assert.equal(api.accountLookups, 2); // 刷新了一次，没有死循环
  pool.closeAll();
});

test('命令超时只关这条通道，登录态保留，下一条命令不受影响', async () => {
  const { pool, config, clients } = makePool({ exec: (cmd) => (cmd === 'sleep 999' ? 'hang' : undefined) });
  const asset = config.assets['web-1'];
  const r = await pool.run(asset, 'ops', 'sleep 999', 50);
  assert.equal(r.timedOut, true);
  assert.equal(clients[0].ended, true);
  assert.equal(pool.sessions.size, 1);
  assert.equal((await pool.run(asset, 'ops', 'id', 1000)).exitCode, 0);
  pool.closeAll();
});

test('输出超过上限时截断', async () => {
  const big = 'x'.repeat(300 * 1024);
  const { pool, config } = makePool({ exec: () => big });
  const r = await pool.run(config.assets['web-1'], 'ops', 'cat big', 1000);
  assert.equal(r.truncated, true);
  assert.equal(r.stdout.length, 256 * 1024);
  pool.closeAll();
});

test('status 只给元数据，closeAll 后清空', async () => {
  const { pool } = makePool();
  await pool.ensureLogin();
  const s = pool.status();
  assert.equal(s.length, 1);
  assert.deepEqual(Object.keys(s[0]).sort(), ['account', 'asset', 'connectedAt', 'expiresAt', 'remainingMinutes']);
  assert.equal(pool.closeAll('test'), 1);
  assert.equal(pool.status().length, 0);
});

// ---------- 健壮性 ----------
test('多字节字符被分块切开时不乱码', async () => {
  const zh = Buffer.from('中文输出\n');
  const { pool, config } = makePool({ exec: () => [zh.subarray(0, 4), zh.subarray(4)] });
  const r = await pool.run(config.assets['web-1'], 'ops', 'echo', 1000);
  assert.equal(r.stdout, '中文输出\n');
  pool.closeAll();
});

test('超时后通道迟迟不关也能返回', async () => {
  const { pool, config, clients } = makePool({ exec: (cmd) => (cmd === 'stuck' ? 'stuck' : undefined) }, { killGraceMs: 30 });
  const asset = config.assets['web-1'];
  const r = await pool.run(asset, 'ops', 'stuck', 20);
  assert.equal(r.timedOut, true);
  assert.equal(clients[0].lastStream.destroyed, true);
  assert.equal((await pool.run(asset, 'ops', 'id', 1000)).exitCode, 0);
  pool.closeAll();
});

test('通道打不开时报错并断开这条连接，登录态保留', async () => {
  const { pool, config, clients } = makePool({ exec: () => 'openfail' });
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /打开执行通道失败/);
  assert.equal(clients[0].ended, true);
  assert.equal(pool.sessions.size, 1);
  pool.closeAll();
});

// ---------- 远端超时包装与主机名核对 ----------
test('远端 timeout 包装：引号安全；主机名核对不包装，且只核对一次', async () => {
  const { JmsService, shQuote } = await import('../src/service.js');
  assert.equal(shQuote("echo 'a b'"), `'echo '\\''a b'\\'''`);
  const { pool, config, allExecs } = makePool();
  const svc = new JmsService(config, pool);
  const r = await svc.exec({ asset: 'web-1', command: "echo 'hi' && sleep 1", timeout_sec: 7 });
  assert.equal(r.exitCode, 0);
  assert.equal(r.timedOut, undefined);
  await svc.exec({ asset: 'web-1', command: 'uptime' });
  assert.deepEqual(allExecs(), ['hostname', `timeout -k 5 7 bash -c 'echo '\\''hi'\\'' && sleep 1'`, `timeout -k 5 60 bash -c 'uptime'`]);
  pool.closeAll();
});

test('主机名对不上时不执行命令', async () => {
  const { JmsService } = await import('../src/service.js');
  const { pool, config, allExecs } = makePool({ exec: (cmd) => (cmd === 'hostname' ? 'other-host\n' : undefined) });
  await assert.rejects(new JmsService(config, pool).exec({ asset: 'web-1', command: 'rm -rf /tmp/x' }), /主机名核对失败：期望 web-1，实际 other-host/);
  assert.deepEqual(allExecs(), ['hostname']);
  pool.closeAll();
});

test('远端 timeout 退出码 124/137 视为超时并说明', async () => {
  const { JmsService } = await import('../src/service.js');
  for (const code of [124, 137]) {
    const { pool, config } = makePool({ exitCode: (cmd) => (cmd.startsWith('timeout') ? code : 0) });
    const r = await new JmsService(config, pool).exec({ asset: 'web-1', command: 'sleep 99', timeout_sec: 1 });
    assert.equal(r.timedOut, true);
    assert.match(r.note, /远端 timeout 已结束/);
    pool.closeAll();
  }
});

test('资产关闭 remoteTimeout 时原样执行', async () => {
  const { JmsService } = await import('../src/service.js');
  const raw = structuredClone(RAW);
  raw.assets['web-1'].remoteTimeout = false;
  const { pool, config, allExecs } = makePool({}, {}, raw);
  const r = await new JmsService(config, pool).exec({ asset: 'web-1', command: 'uptime' });
  assert.equal(r.exitCode, 0);
  assert.equal(allExecs()[1], 'uptime');
  pool.closeAll();
});

test('jms_logout 结束登录态并清空主机名核对记录，之后重新登录', async () => {
  const { JmsService } = await import('../src/service.js');
  const { pool, config, api, allExecs } = makePool();
  const svc = new JmsService(config, pool);
  await svc.exec({ asset: 'web-1', command: 'id' });
  assert.deepEqual(svc.logout(), { closed: 1 });
  assert.equal(svc.list().activeSessions.length, 0);
  await svc.exec({ asset: 'web-1', command: 'id' });
  assert.equal(api.logins, 2);
  assert.equal(allExecs().filter((c) => c === 'hostname').length, 2);
  pool.closeAll();
});

// ---------- 弹窗文案 ----------
test('登录弹窗：说明为什么要密码、谁触发的、密码怎么处理、多久自动关闭，并分密码与动态码两步', async () => {
  const { pool, config, seen } = makePool();
  await pool.run(config.assets['web-1'], 'ops', 'id', 1000);
  const pw = seen.password[0];
  assert.equal(pw.title, 'JumpServer 登录 - alice');
  assert.equal(pw.headline, '输入 JumpServer 登录密码');
  assert.equal(pw.okLabel, '登录');
  assert.equal(pw.timeoutSec, 300);
  assert.match(pw.detail, /AI 助手请求在 web-1 上以 ops 执行命令，需要先登录 JumpServer/);
  assert.match(pw.detail, /用户：alice（koko\.test）/);
  assert.match(pw.detail, /为什么要输入密码：/);
  assert.match(pw.detail, /不会保存、不写入日志，也不会交给 AI/);
  assert.match(pw.detail, /最长 1 小时/);
  assert.match(pw.detail, /第 1 步 \/ 共 2 步 · 5 分钟内未输入，窗口将自动关闭/);
  const otp = seen.otp[0];
  assert.equal(otp.headline, '输入 MFA 动态码');
  assert.equal(otp.okLabel, '验证');
  assert.equal(otp.timeoutSec, 120);
  assert.match(otp.detail, /密码已通过/);
  assert.match(otp.detail, /第 2 步 \/ 共 2 步 · 2 分钟内未输入，窗口将自动关闭/);
  assert.equal(pw.error, null);
  assert.ok(!pw.description.includes('⚠️'));
  assert.ok(pw.description.startsWith('输入 JumpServer 登录密码')); // 整段文字给 pinentry 与兜底样式用
  pool.closeAll();
});

test('登录弹窗：特权账号明确标注；没有触发信息时不写', async () => {
  const { pool, config, seen } = makePool();
  await pool.run(config.assets['web-1'], 'admin', 'id', 1000);
  assert.match(seen.password[0].detail, /以 admin（特权账号） 执行命令/);
  pool.closeAll();
  assert.ok(!loginDescription({ user: 'u', host: 'h', ttlMs: 24 * 3600_000, step: 'password' }).includes('AI 助手请求'));
  assert.ok(loginDescription({ user: 'u', host: 'h', ttlMs: 24 * 3600_000, step: 'password' }).includes('最长 24 小时'));
});

// ---------- 输错时的提示与重输 ----------
test('密码输错且剩余次数充足：弹窗里写明原因并让用户重输，不打扰 AI', async () => {
  const { pool, api, seen, shown, passwords, prompts } = makePool({ correctPassword: 'right-pw', password: ['wrong-pw', 'right-pw'], remaining: 6 });
  await pool.ensureLogin();
  assert.equal(passwords(), 2);
  assert.equal(api.logins, 2);
  assert.equal(prompts(), 1); // 第一次密码就没过，动态码只问了一次
  assert.match(seen.password[1].description, /^⚠️ 密码不正确，还剩 6 次机会。请重新输入。/);
  assert.deepEqual(shown.errors, []);
  assert.equal(pool.sessions.size, 1);
  pool.closeAll();
});

test('密码输错且剩余次数不足：不再让用户当场重输，弹出提示框说明剩余次数与锁定风险', async () => {
  const { pool, shown, passwords } = makePool({ correctPassword: 'right-pw', password: 'wrong-pw', remaining: 2 });
  await assert.rejects(pool.ensureLogin(), /用户名或密码错误/);
  assert.equal(passwords(), 1);
  assert.equal(shown.errors.length, 1);
  assert.equal(shown.errors[0].title, 'JumpServer 登录失败 - alice');
  assert.match(shown.errors[0].message, /密码不正确，还剩 2 次机会/);
  assert.match(shown.errors[0].message, /锁定账号 30 分钟/);
  assert.equal(pool.sessions.size, 0);
});

test('密码连续输错最多重输 2 次（共 3 次），之后弹出失败提示', async () => {
  const { pool, shown, passwords } = makePool({ correctPassword: 'right-pw', password: 'wrong-pw', remaining: 6 });
  await assert.rejects(pool.ensureLogin(), /用户名或密码错误/);
  assert.equal(passwords(), 3);
  assert.equal(shown.errors.length, 1);
});

test('动态码输错：弹窗里写明原因并让用户重输，密码不用再输', async () => {
  const { pool, seen, shown, passwords, prompts } = makePool({ otp: ['000000', '123456'] });
  await pool.ensureLogin();
  assert.equal(passwords(), 1);
  assert.equal(prompts(), 2);
  assert.match(seen.otp[1].description, /^⚠️ 动态码不正确/);
  assert.deepEqual(shown.errors, []);
  pool.closeAll();
});

test('动态码连续输错 3 次：提示用户等新动态码，不再继续', async () => {
  const { pool, shown, prompts } = makePool({ otp: '000000' });
  await assert.rejects(pool.ensureLogin(), /MFA 验证失败/);
  assert.equal(prompts(), 3);
  assert.equal(shown.errors.length, 1);
  assert.match(shown.errors[0].message, /动态码验证失败.*新的动态码/);
});

test('用户主动取消不算失败，不弹错误提示', async () => {
  const a = makePool({ password: null });
  await assert.rejects(a.pool.ensureLogin(), /未输入密码/);
  const b = makePool({ otp: null });
  await assert.rejects(b.pool.ensureLogin(), /未输入 OTP/);
  assert.deepEqual([...a.shown.errors, ...b.shown.errors], []);
});

test('网络不通时提示检查 JumpServer 地址是否可达', async () => {
  const { JmsApiError } = await import('../src/jumpserver.js');
  const { failureMessage } = await import('../src/session.js');
  assert.match(failureMessage(new JmsApiError('无法连接 JumpServer https://x: ECONNRESET', { code: 'network' })), /本机可以访问配置的 JumpServer 地址/);
  assert.match(failureMessage(new JmsApiError('登录失败: boom')), /^登录失败：登录失败: boom/);
});

test('登录成功后发非打断式通知，写明用户与有效期', async () => {
  const { pool, shown } = makePool();
  await pool.ensureLogin();
  assert.equal(shown.notices.length, 1);
  assert.equal(shown.notices[0].title, 'JumpServer 已登录');
  assert.match(shown.notices[0].message, /alice 登录成功，有效期至 .+期间 AI 连接各服务器不再需要输入/);
  pool.closeAll();
});

// ---------- 特殊字符 ----------
const NASTY = 'p@ss"w\\o\'rd%&;$`!#中文 空格 ';

test('含引号、反斜杠、%、$、反引号、中文和首尾空格的密码，原样交给登录接口', async () => {
  const { pool, api } = makePool({ password: NASTY });
  await pool.ensureLogin();
  assert.deepEqual(api.passwordsSeen, [NASTY]);
  pool.closeAll();
});

test('弹窗输出解析：特殊字符密码经 osascript 与 pinentry 都能原样还原', () => {
  assert.equal(parseOsascriptPassword(`${NASTY}\n`), NASTY);
  const assuan = `OK\nD ${NASTY.replace(/%/g, '%25')}\nOK\n`;
  assert.equal(parsePinentryPassword(assuan), NASTY);
  // 密码里本来就含 "%0A" 字样时，不能被误还原成换行
  assert.equal(parsePinentryPassword('D a%250Ab\n'), 'a%0Ab');
});

test('提示框文本含引号、反斜杠、换行时 AppleScript 与 Assuan 转义正确', async () => {
  const { escAppleScript, escAssuan } = await import('../src/prompt.js');
  assert.equal(escAppleScript('密码 "x"\\y\n第二行'), '密码 \\"x\\"\\\\y\\n第二行');
  assert.equal(escAssuan('a%b\r\nc'), 'a%25b%0D%0Ac');
});

test('弹窗文本转义：AppleScript 换行与引号、Assuan 百分号编码', async () => {
  const { escAppleScript, escAssuan } = await import('../src/prompt.js');
  assert.equal(escAppleScript('a "b"\nc\\d'), 'a \\"b\\"\\nc\\\\d');
  assert.equal(escAssuan('50%\n下一行'), '50%25%0A下一行');
});

// ---------- 弹窗超时 ----------
test('弹窗超时：通知用户窗口已关闭，给 AI 明确原因，不再弹错误提示框', async () => {
  const a = makePool({ password: 'TIMEOUT' });
  await assert.rejects(a.pool.ensureLogin(), (e) => e.code === 'prompt_timeout' && /密码窗口等待 5 分钟无人输入，已自动关闭/.test(e.message));
  assert.equal(a.api.logins, 0);
  assert.deepEqual(a.shown.errors, []);
  assert.equal(a.shown.notices[0].title, 'JumpServer 登录窗口已超时');
  assert.match(a.shown.notices[0].message, /5 分钟内没有输入.*让 AI 重新发起/);

  const b = makePool({ otp: 'TIMEOUT' });
  await assert.rejects(b.pool.ensureLogin(), (e) => e.code === 'prompt_timeout' && /动态码窗口等待 2 分钟/.test(e.message));
  assert.deepEqual(b.shown.errors, []);
  assert.equal(b.pool.sessions.size, 0);
});

test('等待预算：覆盖密码 3 次与动态码 3 次的最长弹窗时间', async () => {
  const { LOGIN_BUDGET_MS } = await import('../src/session.js');
  assert.equal(LOGIN_BUDGET_MS, (3 * 300 + 3 * 120 + 60) * 1000);
});

test('弹窗整段文字：错误提示置顶，标题与说明依次排开', async () => {
  const { composeDescription, PromptTimeoutError } = await import('../src/prompt.js');
  assert.equal(composeDescription({ headline: 'H', detail: 'D', error: null }), 'H\n\nD');
  assert.equal(composeDescription({ headline: 'H', detail: 'D', error: 'E' }), '⚠️ E\n\nH\n\nD');
  const e = new PromptTimeoutError(300);
  assert.equal(e.code, 'prompt_timeout');
  assert.match(e.message, /5 分钟/);
});

// ---------- 注销与在途登录 ----------
const gate = () => { let open; const p = new Promise((r) => { open = r; }); return { p, open }; };

test('注销发生在等待密码期间：不再提交密码，登录作废，不写入登录态', async () => {
  const g = gate();
  const { pool, config, api } = makePool({}, { passwordPrompt: async () => { await g.p; return 'pw-secret-1'; } });
  const run = pool.run(config.assets['web-1'], 'ops', 'id', 1000);
  await new Promise((r) => setImmediate(r));
  pool.closeAll('手动注销');
  g.open();
  await assert.rejects(run, /已执行注销/);
  assert.equal(api.logins, 0);
  assert.equal(pool.sessions.size, 0);
});

test('注销发生在等待动态码期间：认证结果被丢弃，登录态不被写入', async () => {
  const g = gate();
  const { pool, config, api } = makePool({}, { otpPrompt: async () => { await g.p; return '123456'; } });
  const run = pool.run(config.assets['web-1'], 'ops', 'id', 1000);
  await new Promise((r) => setImmediate(r));
  pool.closeAll('手动注销');
  g.open();
  await assert.rejects(run, /已执行注销/);
  assert.equal(api.logins, 1);
  assert.equal(pool.sessions.size, 0);
  assert.equal(pool.pending.size, 0);
});

test('注销之后的新调用另起一次登录，不复用已作废的登录', async () => {
  const g = gate();
  let n = 0;
  const { pool, config, api } = makePool({}, { passwordPrompt: async () => { if (++n === 1) await g.p; return 'pw-secret-1'; } });
  const first = pool.run(config.assets['web-1'], 'ops', 'id', 1000);
  await new Promise((r) => setImmediate(r));
  pool.closeAll('手动注销');
  const second = await pool.run(config.assets['web-1'], 'ops', 'id', 1000);
  assert.equal(second.exitCode, 0);
  g.open();
  await assert.rejects(first, /已执行注销/);
  assert.equal(api.logins, 1);
  assert.equal(pool.sessions.size, 1); // 第二次登录的登录态没有被第一次的收尾清掉
  pool.closeAll();
});

// ---------- 账号重名 ----------
test('账号名同时匹配多个授权账号：拒绝，不取第一个', async () => {
  const { pool, config, api } = makePool();
  api.assetAccounts = async () => [
    { alias: 'alias-1', name: 'ops', username: 'x1' },
    { alias: 'alias-2', name: 'y', username: 'ops' },
  ];
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /匹配到多个授权账号/);
  assert.equal(api.tokens.length, 0);
  pool.closeAll();
});

test('普通账号名撞到特权账号：拒绝，不申请令牌', async () => {
  const { pool, config, api } = makePool();
  api.assetAccounts = async () => [{ alias: 'alias-admin', name: 'ops', username: 'admin' }];
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 1000), /实际对应特权账号/);
  assert.equal(api.tokens.length, 0);
  pool.closeAll();
});

// ---------- P2 ----------
test('IPC 逐行解析：多字节中文被切在两个数据块之间也不损坏', async () => {
  const { lineReader } = await import('../src/ipc.js');
  const got = [];
  const feed = lineReader((l) => got.push(l));
  const b = Buffer.from(`${JSON.stringify({ s: '中文命令' })}\n`);
  feed(b.subarray(0, 7)); // 切在“中”的中间
  feed(b.subarray(7, 11));
  feed(b.subarray(11));
  assert.deepEqual(got.map((l) => JSON.parse(l)), [{ s: '中文命令' }]);
});

test('登录过期后重新登录，主机名重新核对', async () => {
  const { JmsService } = await import('../src/service.js');
  let now = 1_000_000;
  const { pool, config, allExecs } = makePool({}, { now: () => now });
  const svc = new JmsService(config, pool);
  await svc.exec({ asset: 'web-1', command: 'id' });
  await svc.exec({ asset: 'web-1', command: 'id' });
  assert.equal(allExecs().filter((c) => c === 'hostname').length, 1); // 同一登录态内只核对一次
  now += config.ttlMs + 1;
  await svc.exec({ asset: 'web-1', command: 'id' });
  assert.equal(allExecs().filter((c) => c === 'hostname').length, 2);
  pool.closeAll();
});

test('KoKo 不确认执行通道时，到时报错而不是一直等', async () => {
  const { pool, config } = makePool({ exec: () => 'noopen' });
  const t0 = Date.now();
  await assert.rejects(pool.run(config.assets['web-1'], 'ops', 'id', 50), /打开执行通道超时/);
  assert.ok(Date.now() - t0 < 2000);
  pool.closeAll();
});
