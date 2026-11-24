import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JmsApiError, JumpServerApi, parseJmsDate } from '../src/jumpserver.js';

/** 按顺序返回预设响应的假 fetch，并记录每次请求。 */
function fakeFetch(responses) {
  const calls = [];
  const queue = [...responses];
  const impl = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined });
    const next = queue.shift();
    if (next instanceof Error) throw next;
    const headers = new Headers();
    for (const c of next.cookies ?? []) headers.append('set-cookie', c);
    return new Response(JSON.stringify(next.body ?? {}), { status: next.status ?? 200, headers });
  };
  return { impl, calls };
}

const api = (responses) => {
  const f = fakeFetch(responses);
  return { client: new JumpServerApi({ baseUrl: 'https://js.test/', fetchImpl: f.impl }), calls: f.calls };
};

test('过期时间解析：JumpServer 的日期格式', () => {
  assert.equal(parseJmsDate('2026/11/24 11:03:35 +0800'), Date.parse('2026-11-24T11:03:35+08:00'));
  assert.equal(parseJmsDate('2026/11/24 11:03:35 -0530'), Date.parse('2026-11-24T11:03:35-05:30'));
  assert.equal(parseJmsDate('not a date'), null);
  assert.equal(parseJmsDate(undefined), null);
});

test('登录：密码通过后要求 MFA，提交 OTP，再次认证拿到令牌，会话 cookie 全程带上', async () => {
  const { client, calls } = api([
    // 真实响应只有 error、msg、data 三个字段，没有 code
    { status: 200, body: { error: 'mfa_required', msg: 'MFA authentication required', data: { choices: ['otp'], url: '/api/v1/authentication/mfa/challenge/' } }, cookies: ['sessionid=abc; Path=/', 'csrftoken=xyz; Path=/'] },
    { status: 200, body: { msg: 'ok' } },
    { status: 201, body: { token: 'bearer-token', keyword: 'Bearer', date_expired: '2026/11/24 11:03:35 +0800' } },
  ]);
  let otpAsked = 0;
  const r = await client.login('alice', 'pw', async () => { otpAsked++; return '123456'; });
  assert.deepEqual(r, { token: 'bearer-token', expiresAt: Date.parse('2026-11-24T11:03:35+08:00') });
  assert.equal(otpAsked, 1);
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url}`), [
    'POST https://js.test/api/v1/authentication/auth/',
    'POST https://js.test/api/v1/authentication/mfa/challenge/',
    'POST https://js.test/api/v1/authentication/auth/',
  ]);
  assert.deepEqual(calls[1].body, { type: 'otp', code: '123456' });
  assert.equal(calls[1].headers.cookie, 'sessionid=abc; csrftoken=xyz');
  assert.equal(calls[1].headers['x-csrftoken'], 'xyz');
  assert.deepEqual(calls[2].body, { username: 'alice', password: 'pw' });
});

test('登录：账号没开 MFA 时不弹 OTP', async () => {
  const { client } = api([{ status: 201, body: { token: 't', date_expired: '2026/11/24 11:03:35 +0800' } }]);
  const r = await client.login('alice', 'pw', async () => { throw new Error('不应被调用'); });
  assert.equal(r.token, 't');
});

test('登录：密码错误时给出服务端提示（含剩余次数），且错误里不含密码', async () => {
  const { client } = api([{ status: 400, body: { code: 'password_failed', msg: 'incorrect, You have 7 more attempt(s)' } }]);
  await assert.rejects(client.login('alice', 's3cret-pw', async () => '1'), (e) => {
    assert.match(e.message, /用户名或密码错误.*7 more attempt/);
    assert.equal(e.code, 'password_failed');
    assert.ok(!e.message.includes('s3cret-pw'));
    return true;
  });
});

test('登录：OTP 被服务端拒绝（非 400）时立即报错，不再继续认证', async () => {
  const { client, calls } = api([
    { status: 200, body: { code: 'mfa_required', data: { choices: ['otp'] } } },
    { status: 403, body: { code: 'mfa_failed', msg: 'Code is invalid' } },
  ]);
  await assert.rejects(client.login('alice', 'pw', async () => '000000'), /MFA 验证失败: Code is invalid/);
  assert.equal(calls.length, 2);
});

test('登录：MFA 方式不含 OTP 时明确报不支持', async () => {
  const { client } = api([{ status: 200, body: { code: 'mfa_required', data: { choices: ['face'] } } }]);
  await assert.rejects(client.login('alice', 'pw', async () => '1'), /暂不支持/);
});

test('网络不可达时报可读错误', async () => {
  const { client } = api([Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } })]);
  await assert.rejects(client.login('alice', 'pw', async () => '1'), (e) => e.code === 'network' && /ECONNRESET/.test(e.message));
});

test('查询资产与账号：按名称找 id，账号别名来自授权列表', async () => {
  const { client, calls } = api([
    { body: { results: [{ id: 'id-1', name: 'web-10' }, { id: 'id-2', name: 'web-1' }] } },
    { body: { permed_accounts: [{ alias: 'al-1', name: 'ops', username: 'ops', has_secret: true }] } },
  ]);
  assert.equal(await client.findAssetId('tk', 'web-1'), 'id-2');
  assert.deepEqual(await client.assetAccounts('tk', 'id-2'), [{ alias: 'al-1', name: 'ops', username: 'ops' }]);
  assert.equal(calls[0].headers.authorization, 'Bearer tk');
  assert.match(calls[0].url, /search=web-1/);
  assert.match(calls[1].url, /\/perms\/users\/self\/assets\/id-2\/$/);
});

test('申请连接令牌：请求体与返回值，401 标为 unauthorized，其余带服务端 code', async () => {
  const { client, calls } = api([
    { status: 201, body: { id: 'tok-id', value: 'tok-secret', is_reusable: false } },
    { status: 401, body: { detail: 'Authentication credentials were not provided.' } },
    { status: 400, body: { code: 'perm_account_invalid', msg: 'Account not found' } },
    { status: 201, body: { id: 'only-id' } },
  ]);
  assert.deepEqual(await client.connectionToken('tk', 'asset-1', 'alias-1'), { id: 'tok-id', value: 'tok-secret' });
  assert.deepEqual(calls[0].body, { asset: 'asset-1', account: 'alias-1', protocol: 'ssh', connect_method: 'ssh_client', input_username: '', input_secret: '', connect_options: {} });
  await assert.rejects(client.connectionToken('tk', 'a', 'b'), (e) => e instanceof JmsApiError && e.code === 'unauthorized');
  await assert.rejects(client.connectionToken('tk', 'a', 'b'), (e) => e.code === 'perm_account_invalid' && /Account not found/.test(e.message));
  await assert.rejects(client.connectionToken('tk', 'a', 'b'), /缺少 id 或 value/);
});

test('登录：动态码输错（HTTP 400）可重输，重输时带上上一次的错误提示，最多 3 次', async () => {
  const mfa = { status: 200, body: { error: 'mfa_required', msg: 'MFA authentication required', data: { choices: ['otp'] } } };
  const bad = { status: 400, body: { code: 'mfa_failed', msg: 'Code is invalid' } };
  const ok = [{ status: 200, body: { msg: 'ok' } }, { status: 201, body: { token: 't' } }];

  const first = api([mfa, bad, ...ok]);
  const seen = [];
  const r = await first.client.login('alice', 'pw', async (ctx) => { seen.push(ctx); return seen.length === 1 ? '000000' : '123456'; });
  assert.equal(r.token, 't');
  assert.deepEqual(seen.map((s) => s.attempt), [1, 2]);
  assert.equal(seen[0].error, null);
  assert.match(seen[1].error, /动态码不正确（Code is invalid）/);

  const third = api([mfa, bad, bad, bad]);
  let asked = 0;
  await assert.rejects(third.client.login('alice', 'pw', async () => { asked++; return '000000'; }), /MFA 验证失败: Code is invalid/);
  assert.equal(asked, 3);
});

test('登录：动态码被限流等非 400 错误时立即停止，不重试', async () => {
  const { client } = api([
    { status: 200, body: { error: 'mfa_required', data: { choices: ['otp'] } } },
    { status: 403, body: { code: 'block_mfa', msg: 'Too many attempts' } },
  ]);
  let asked = 0;
  await assert.rejects(client.login('alice', 'pw', async () => { asked++; return '1'; }), /Too many attempts/);
  assert.equal(asked, 1);
});

test('登录：密码错误时带上服务端提示的剩余次数', async () => {
  const { remainingAttempts } = await import('../src/jumpserver.js');
  assert.equal(remainingAttempts('incorrect, please try again. You have 7 more attempt(s) (the account will be temporarily locked for 30 minutes)'), 7);
  assert.equal(remainingAttempts('You have 1 more attempt'), 1);
  assert.equal(remainingAttempts('账号已被锁定'), null);
  const { client } = api([{ status: 400, body: { code: 'password_failed', msg: 'You have 5 more attempt(s)' } }]);
  await assert.rejects(client.login('alice', 'pw', async () => '1'), (e) => e.remaining === 5 && e.code === 'password_failed');
});

test('登录：含引号、反斜杠、%、$、反引号、中文和首尾空格的密码，在请求体里逐字节不变', async () => {
  const nasty = 'p@ss"w\\o\'rd%&;$`!#中文 空格 ';
  const { client, calls } = api([{ status: 201, body: { token: 't' } }]);
  await client.login('alice', nasty, async () => '1');
  assert.equal(calls[0].body.password, nasty);
  assert.equal(calls[0].body.username, 'alice');
});
