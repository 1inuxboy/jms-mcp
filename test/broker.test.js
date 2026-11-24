import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startBroker } from '../src/broker.js';
import { request, tokenPath } from '../src/ipc.js';
import { brokerBackend } from '../src/index.js';
import { JmsService } from '../src/service.js';
import { LOGIN_BUDGET_MS } from '../src/session.js';
import { RAW, makePool } from './helpers.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function setup(t, opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'jms-broker-'));
  const cfgPath = join(dir, 'config.json');
  writeFileSync(cfgPath, JSON.stringify(RAW));
  const { pool, config, prompts, passwords, api, clients } = makePool();
  const exits = [];
  const b = await startBroker({
    dir, cfgPath, service: new JmsService(config, pool), log: () => {}, exit: (c) => exits.push(c), ...opts,
  });
  t.after(() => { try { b?.stop('测试结束'); } catch { /* 已停 */ } rmSync(dir, { recursive: true, force: true }); });
  return { dir, cfgPath, b, prompts, passwords, api, clients, exits, pool };
}

test('broker：令牌只有本人可读，错误令牌被拒', async (t) => {
  const { dir, b } = await setup(t);
  if (process.platform !== 'win32') {
    assert.equal(statSync(tokenPath(dir)).mode & 0o777, 0o600);
    assert.equal(statSync(dir).mode & 0o777, 0o700);
  }
  const hello = await request('hello', {}, { dir });
  assert.equal(hello.activeSessions, 0);
  writeFileSync(tokenPath(dir), 'wrong');
  await assert.rejects(request('hello', {}, { dir }), (e) => e.code === 'EAUTH');
  writeFileSync(tokenPath(dir), b.token);
});

test('broker：多个会话共用一次登录（密码和 OTP 各一次），logout 对所有会话生效', async (t) => {
  const { dir, prompts, passwords, api } = await setup(t);
  const args = { asset: 'web-1', command: 'id' };
  // 两个“会话”各自连 broker、并发执行
  const [r1, r2] = await Promise.all([request('exec', args, { dir }), request('exec', args, { dir })]);
  assert.equal(r1.exitCode, 0);
  assert.equal(r2.exitCode, 0);
  assert.equal(passwords(), 1);
  assert.equal(prompts(), 1);
  assert.equal(api.logins, 1);
  const listed = await request('list', {}, { dir });
  assert.equal(listed.activeSessions.length, 1);
  assert.deepEqual(await request('logout', {}, { dir }), { closed: 1 });
  assert.equal((await request('list', {}, { dir })).activeSessions.length, 0);
});

test('broker：业务错误原样返回，不影响后续请求', async (t) => {
  const { dir } = await setup(t);
  await assert.rejects(request('exec', { asset: 'nope', command: 'id' }, { dir }), /未知资产/);
  await assert.rejects(request('exec', { asset: 'web-1', command: 'id', account: 'admin' }, { dir }), /特权账号/);
  assert.equal((await request('exec', { asset: 'web-1', command: 'id' }, { dir })).exitCode, 0);
});

test('broker：同一目录只允许一个实例', async (t) => {
  const { dir, cfgPath } = await setup(t);
  const exits = [];
  const second = await startBroker({ dir, cfgPath, service: new JmsService(makePool().config, makePool().pool), log: () => {}, exit: (c) => exits.push(c) });
  assert.equal(second, null);
  assert.deepEqual(exits, [0]);
  assert.equal((await request('hello', {}, { dir })).activeSessions, 0); // 原实例仍可用
});

test('broker：有登录态时拒绝 ifIdle 关停，登录态结束且空闲后自动退出', async (t) => {
  const { dir, exits } = await setup(t, { idleExitMs: 50 });
  await request('exec', { asset: 'web-1', command: 'id' }, { dir });
  await assert.rejects(request('shutdown', { ifIdle: true }, { dir }), (e) => e.code === 'EBUSY');
  await sleep(150);
  assert.deepEqual(exits, []); // 有登录态就不退出
  await request('logout', {}, { dir });
  await sleep(200);
  assert.deepEqual(exits, [0]);
  assert.equal(existsSync(tokenPath(dir)), false);
});

test('MCP 后端：broker 跑旧代码且有登录态时提示 stale', async () => {
  const calls = [];
  const backend = brokerBackend({
    cfgPath: '/nonexistent',
    ensure: async () => ({ stale: true }),
    call: async (op, args, opts) => { calls.push({ op, opts }); return { activeSessions: [] }; },
  });
  const r = await backend.list();
  assert.match(r.warning, /旧代码或旧配置/);
  await backend.exec({ asset: 'web-1', command: 'id', timeout_sec: 10 });
  assert.equal(calls[1].opts.timeoutMs, 10_000 + LOGIN_BUDGET_MS);
});
