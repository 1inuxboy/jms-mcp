// jms 业务逻辑：资产/账号校验、主机名核对、执行与注销。broker 与进程内模式共用。
import { resolveAccount } from './config.js';
import { SessionPool } from './session.js';

export const DEFAULT_TIMEOUT_SEC = 60;
export const MAX_TIMEOUT_SEC = 600;
/** 远端 TERM 后再等多久发 KILL */
const REMOTE_KILL_AFTER_SEC = 5;
/** 本地兜底比远端多等的时间，保证正常情况下由远端先结束并带回退出码 */
const LOCAL_SLACK_SEC = REMOTE_KILL_AFTER_SEC + 5;
/** timeout(1) 超时退出码：124 = TERM 后结束；137 = 128+KILL */
const REMOTE_TIMEOUT_CODES = new Set([124, 137]);

/** 单引号包裹，供 bash -c 使用 */
export function shQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/** 用远端 timeout 包装命令：超时后 timeout 会结束它创建的整个进程组。 */
export function wrapRemoteTimeout(command, sec) {
  return `timeout -k ${REMOTE_KILL_AFTER_SEC} ${sec} bash -c ${shQuote(command)}`;
}

export class JmsService {
  constructor(config, pool = new SessionPool(config)) {
    this.config = config;
    this.pool = pool;
    /** 已核对过主机名的（资产, 账号）；登录态或资产缓存失效（pool.generation 变化）后作废 */
    this.verified = new Set();
    this.verifiedGeneration = 0;
  }

  list() {
    return {
      koko: `${this.config.koko.host}:${this.config.koko.port}`,
      ttlHours: this.config.ttlMs / 3600_000,
      assets: Object.values(this.config.assets).map((a) => ({
        name: a.name,
        description: a.description,
        defaultAccount: a.defaultAccount,
        accounts: a.accounts,
        privilegedAccounts: a.privilegedAccounts,
      })),
      activeSessions: this.pool.status(),
    };
  }

  /** 每个（资产, 账号）首次使用前核对主机名，防止资产配错时在别的机器上执行。 */
  async #verifyHostname(asset, account, timeoutMs) {
    if (!asset.expectHostname) return;
    // 先确保登录态有效：已过期时在这里重新登录，generation 才反映当前登录
    await this.pool.ensureLogin({ asset: asset.name, account, privileged: asset.privilegedAccounts.includes(account) });
    const key = `${asset.name}|${account}`;
    if (this.verifiedGeneration !== this.pool.generation) { this.verified.clear(); this.verifiedGeneration = this.pool.generation; }
    if (this.verified.has(key)) return;
    const r = await this.pool.run(asset, account, 'hostname', Math.min(timeoutMs, 15_000));
    const got = r.stdout.trim().split('.')[0];
    if (r.exitCode !== 0 || got !== asset.expectHostname) {
      throw new Error(`主机名核对失败：期望 ${asset.expectHostname}，实际 ${got || '(空)'}，未执行命令`);
    }
    if (this.verifiedGeneration !== this.pool.generation) { this.verified.clear(); this.verifiedGeneration = this.pool.generation; } // 核对期间重新登录过：只认新登录下的结果
    this.verified.add(key);
  }

  /** 失败时抛出可直接展示给用户的错误。 */
  async exec({ asset: assetName, command, account, privileged, timeout_sec }) {
    const asset = this.config.assets[assetName];
    if (!asset) throw new Error(`未知资产 ${assetName}，可用: ${Object.keys(this.config.assets).join(', ')}`);
    if (typeof command !== 'string' || !command) throw new Error('command 不能为空');
    const acc = resolveAccount(asset, account, privileged === true);
    const sec = timeout_sec ?? DEFAULT_TIMEOUT_SEC;
    if (!(Number.isInteger(sec) && sec >= 1 && sec <= MAX_TIMEOUT_SEC)) throw new Error(`timeout_sec 必须是 1-${MAX_TIMEOUT_SEC} 的整数`);
    const wrap = asset.remoteTimeout;
    const remoteCmd = wrap ? wrapRemoteTimeout(command, sec) : command;
    const timeoutMs = (wrap ? sec + LOCAL_SLACK_SEC : sec) * 1000;
    try {
      await this.#verifyHostname(asset, acc, sec * 1000);
      const r = await this.pool.run(asset, acc, remoteCmd, timeoutMs);
      const remoteTimedOut = wrap && !r.timedOut && REMOTE_TIMEOUT_CODES.has(r.exitCode);
      let note;
      if (remoteTimedOut) note = `超过 ${sec}s，远端 timeout 已结束该命令及其子进程（退出码 ${r.exitCode}；若命令本身就以 124/137 退出会被误判为超时）`;
      else if (r.timedOut && wrap) note = `超过 ${sec}s 且远端未按时结束，本地已关闭通道；远端进程可能仍在运行，请人工确认`;
      else if (r.timedOut) note = `超过 ${sec}s 已关闭通道；该资产未启用远端超时，远端进程可能仍在运行`;
      return {
        asset: asset.name,
        account: acc,
        exitCode: r.exitCode,
        ...(r.signal ? { signal: r.signal } : {}),
        ...(r.timedOut || remoteTimedOut ? { timedOut: true, note } : {}),
        ...(r.truncated ? { truncated: true } : {}),
        stdout: r.stdout,
        stderr: r.stderr,
        sessionExpiresAt: new Date(r.sessionExpiresAt).toISOString(),
      };
    } catch (e) {
      throw new Error(`${asset.name} / ${acc}: ${e.message}`);
    }
  }

  /** 结束登录态（对所有 AI 会话生效），之后再执行命令要重新输入密码和 OTP。 */
  logout() {
    this.verified.clear();
    return { closed: this.pool.closeAll('手动注销') };
  }
}
