// 常驻 broker：全机一个，持有经过 MFA 的 SSH 连接，供所有 AI 会话的 MCP 进程复用。
// 没有活动连接且空闲一段时间后自动退出；由 MCP 进程按需拉起。
import { timingSafeEqual } from 'node:crypto';
import { createServer, connect } from 'node:net';
import { rmSync } from 'node:fs';
import { configPath as defaultConfigPath, loadConfig } from './config.js';
import { buildId, endpoint, ensureRuntimeDir, lineReader, newToken, runtimeDir, tokenPath, writeToken } from './ipc.js';
import { JmsService } from './service.js';
import { SessionPool } from './session.js';

const IDLE_EXIT_MS = 10 * 60_000;

function sameToken(a, b) {
  const x = Buffer.from(String(a ?? ''));
  const y = Buffer.from(String(b ?? ''));
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
}

/** unix socket 文件残留时判断是否还有 broker 在监听 */
function probe(path) {
  return new Promise((resolve) => {
    const s = connect(path);
    s.on('connect', () => { s.destroy(); resolve(true); });
    s.on('error', () => resolve(false));
  });
}

function listen(server, path) {
  return new Promise((resolve, reject) => {
    const onErr = (e) => { server.off('listening', onOk); reject(e); };
    const onOk = () => { server.off('error', onErr); resolve(); };
    server.once('error', onErr);
    server.once('listening', onOk);
    server.listen(path);
  });
}

/**
 * @param {{dir?: string, cfgPath?: string, service?: JmsService, idleExitMs?: number, exit?: (code: number) => void, log?: (m: string) => void}} [opts]
 */
export async function startBroker(opts = {}) {
  const dir = ensureRuntimeDir(opts.dir ?? runtimeDir());
  const cfgPath = opts.cfgPath ?? defaultConfigPath();
  const log = opts.log ?? ((m) => process.stderr.write(`${new Date().toISOString()} [broker] ${m}\n`));
  let service = opts.service;
  if (!service) {
    const config = loadConfig(cfgPath);
    service = new JmsService(config, new SessionPool(config, { log }));
  }
  const idleExitMs = opts.idleExitMs ?? IDLE_EXIT_MS;
  const exit = opts.exit ?? ((code) => process.exit(code));
  const id = buildId(cfgPath);
  const token = newToken();
  const path = endpoint(dir);
  let lastActivity = Date.now();
  let busy = 0;

  const handle = async (msg) => {
    if (!sameToken(msg.token, token)) return { ok: false, code: 'EAUTH', error: '令牌不匹配' };
    lastActivity = Date.now();
    switch (msg.op) {
      case 'hello':
        return { ok: true, result: { pid: process.pid, buildId: id, activeSessions: service.pool.sessions.size } };
      case 'list':
        return { ok: true, result: { ...service.list(), broker: { pid: process.pid, buildId: id } } };
      case 'exec':
        return { ok: true, result: await service.exec(msg.args ?? {}) };
      case 'logout':
        return { ok: true, result: service.logout(msg.args ?? {}) };
      case 'shutdown':
        if (msg.args?.ifIdle && (service.pool.sessions.size > 0 || busy > 1)) {
          return { ok: false, code: 'EBUSY', error: '仍有活动连接，未退出' };
        }
        setImmediate(() => stop('收到 shutdown'));
        return { ok: true, result: { stopping: true } };
      default:
        return { ok: false, error: `未知操作 ${msg.op}` };
    }
  };

  const server = createServer((sock) => {
    sock.on('error', () => {});
    sock.on('data', lineReader(async (line) => {
      busy++;
      let reply;
      try {
        reply = await handle(JSON.parse(line));
      } catch (e) {
        reply = { ok: false, error: e.message };
      } finally {
        busy--;
        lastActivity = Date.now();
      }
      if (!sock.destroyed) sock.write(JSON.stringify(reply) + '\n');
    }));
  });

  try {
    await listen(server, path);
  } catch (e) {
    if (e.code !== 'EADDRINUSE') throw e;
    if (process.platform === 'win32' || await probe(path)) {
      log('已有 broker 在运行，本进程退出');
      exit(0);
      return null;
    }
    rmSync(path, { force: true }); // 上次异常退出残留的 socket 文件
    await listen(server, path);
  }
  writeToken(token, dir);
  log(`已启动 pid=${process.pid} build=${id} endpoint=${path}`);

  const idleTimer = setInterval(() => {
    if (service.pool.sessions.size === 0 && service.pool.pending.size === 0 && busy === 0 && Date.now() - lastActivity > idleExitMs) {
      stop('无活动连接且空闲超时');
    }
  }, Math.min(60_000, idleExitMs));

  let stopped = false;
  function stop(reason) {
    if (stopped) return;
    stopped = true;
    log(`退出: ${reason}`);
    clearInterval(idleTimer);
    service.pool.closeAll(`broker 退出: ${reason}`);
    server.close();
    rmSync(tokenPath(dir), { force: true });
    if (process.platform !== 'win32') rmSync(path, { force: true });
    exit(0);
  }

  return { stop, server, path, token, service };
}

export async function runBroker() {
  const handle = await startBroker();
  if (!handle) return;
  process.on('SIGINT', () => handle.stop('SIGINT'));
  process.on('SIGTERM', () => handle.stop('SIGTERM'));
  process.on('uncaughtException', (e) => process.stderr.write(`${new Date().toISOString()} [broker] 未捕获异常: ${e.stack}\n`));
}
