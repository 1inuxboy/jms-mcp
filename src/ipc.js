// 本机 IPC：MCP 进程（每个 AI 会话一个）↔ 常驻 broker（全机一个，持有 SSH 连接）。
// 通道仅限当前用户：macOS 用 0700 目录下的 unix socket，Windows 用带用户名的命名管道；
// 另外每个请求都要带 broker 启动时生成、只写在用户目录里的随机令牌。
import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmodSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { connect } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC_DIR = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = join(SRC_DIR, 'cli.js');

export function runtimeDir(env = process.env) {
  return env.JMS_MCP_RUNTIME_DIR || join(homedir(), '.jms-mcp');
}

export function ensureRuntimeDir(dir = runtimeDir()) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') chmodSync(dir, 0o700);
  return dir;
}

export function endpoint(dir = runtimeDir(), platform = process.platform) {
  if (platform === 'win32') {
    const tag = createHash('sha256').update(dir.toLowerCase()).digest('hex').slice(0, 8);
    return `\\\\.\\pipe\\jms-mcp-${userInfo().username}-${tag}`;
  }
  const sock = join(dir, 'broker.sock');
  if (Buffer.byteLength(sock) <= 100) return sock;
  // unix socket 路径上限约 104 字节：过长时改放 /tmp 下仅本人可访问的子目录
  const tag = createHash('sha256').update(dir).digest('hex').slice(0, 12);
  const short = `/tmp/jms-mcp-${process.getuid?.() ?? userInfo().username}`;
  mkdirSync(short, { recursive: true, mode: 0o700 });
  chmodSync(short, 0o700);
  return join(short, `${tag}.sock`);
}

export const tokenPath = (dir = runtimeDir()) => join(dir, 'broker.token');
export const logPath = (dir = runtimeDir()) => join(dir, 'broker.log');

export function newToken() {
  return randomBytes(32).toString('hex');
}

export function writeToken(token, dir = runtimeDir()) {
  writeFileSync(tokenPath(dir), token, { mode: 0o600 });
}

function readToken(dir) {
  try { return readFileSync(tokenPath(dir), 'utf8').trim(); } catch { return ''; }
}

/**
 * 代码与配置的指纹：MCP 进程发现 broker 指纹不同（升级了代码或改了配置）时，
 * 若 broker 上没有活动连接就让它退出并换新的。
 */
export function buildId(configPath) {
  const h = createHash('sha256');
  for (const f of readdirSync(SRC_DIR).filter((n) => n.endsWith('.js')).sort()) h.update(f).update(readFileSync(join(SRC_DIR, f)));
  try { h.update(readFileSync(configPath)); } catch { h.update('no-config'); }
  return h.digest('hex').slice(0, 16);
}

/** 逐行 JSON 解析器 */
export function lineReader(onMessage) {
  let buf = '';
  return (chunk) => {
    buf += chunk.toString('utf8');
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (line.trim()) onMessage(line);
    }
  };
}

/** 发一个请求，等一个响应。连接失败时 error.code 为 ENOENT/ECONNREFUSED 等。 */
export function request(op, args = {}, { dir = runtimeDir(), timeoutMs = 30_000 } = {}) {
  return new Promise((resolve, reject) => {
    const sock = connect(endpoint(dir));
    let settled = false;
    const done = (fn, v) => { if (!settled) { settled = true; clearTimeout(timer); sock.destroy(); fn(v); } };
    const timer = setTimeout(() => done(reject, Object.assign(new Error(`broker 响应超时（${Math.round(timeoutMs / 1000)}s）`), { code: 'ETIMEDOUT' })), timeoutMs);
    sock.on('error', (e) => done(reject, e));
    sock.on('close', () => done(reject, Object.assign(new Error('broker 意外断开'), { code: 'EBROKERCLOSED' })));
    sock.on('data', lineReader((line) => {
      let msg;
      try { msg = JSON.parse(line); } catch { return done(reject, new Error('broker 返回了无法解析的数据')); }
      if (msg.ok) done(resolve, msg.result);
      else done(reject, Object.assign(new Error(msg.error), { code: msg.code || 'EBROKER' }));
    }));
    sock.on('connect', () => sock.write(JSON.stringify({ token: readToken(dir), op, args }) + '\n'));
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isDown = (e) => ['ENOENT', 'ECONNREFUSED', 'EBROKERCLOSED'].includes(e.code);

function spawnBroker(dir, env) {
  const log = openSync(logPath(dir), 'a', 0o600);
  const child = spawn(process.execPath, [CLI_PATH, 'broker'], {
    detached: true,
    stdio: ['ignore', log, log],
    windowsHide: true,
    env,
  });
  child.unref();
}

/**
 * 确保 broker 在跑且与当前代码/配置一致；返回 broker 的 hello 信息。
 * broker 指纹不一致且无活动连接时会被替换；有活动连接则继续用旧的（hello.stale=true）。
 */
export async function ensureBroker({ dir = runtimeDir(), configPath, env = process.env, startTimeoutMs = 10_000 } = {}) {
  ensureRuntimeDir(dir);
  const want = buildId(configPath);
  let spawned = false;
  const deadline = Date.now() + startTimeoutMs;
  for (;;) {
    if (Date.now() > deadline) throw new Error(`无法启动或替换 jms broker，详见 ${logPath(dir)}`);
    try {
      const hello = await request('hello', {}, { dir, timeoutMs: 3_000 });
      if (hello.buildId === want) return hello;
      if (hello.activeSessions > 0) return { ...hello, stale: true };
      await request('shutdown', { ifIdle: true }, { dir, timeoutMs: 3_000 }).catch(() => {});
      spawned = false;
      await sleep(300);
      continue;
    } catch (e) {
      // EAUTH：broker 刚启动、令牌尚未落盘，稍等重试即可
      if (e.code === 'EAUTH') { await sleep(200); continue; }
      if (!isDown(e) && e.code !== 'ETIMEDOUT') throw e;
    }
    if (!spawned) { spawnBroker(dir, env); spawned = true; }
    await sleep(200);
  }
}
