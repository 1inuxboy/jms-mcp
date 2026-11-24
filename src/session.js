// 登录态 + 一次性连接令牌：
//  - 登录态：经 JumpServer API 用「密码 + OTP」登录一次，有效期内本机所有 AI 会话共享；
//  - 每条命令：用登录态申请一次性连接令牌（不再要 MFA），用令牌连 KoKo 执行，结束即断开。
import { createHash } from 'node:crypto';
import { Client } from 'ssh2';
import { JumpServerApi } from './jumpserver.js';
import { askOtp, askPassword, composeDescription, notifyUser, showError } from './prompt.js';

/** 密码在弹窗里最多输几次；剩余次数低于下限时不再让用户当场重输，避免把账号锁了 */
const MAX_PASSWORD_ATTEMPTS = 3;
const MIN_REMAINING_FOR_RETRY = 3;
/** 弹窗等待时长：找密码可能要翻密码管理器，给 5 分钟；动态码 30 秒一换，输密码后马上输，给 2 分钟 */
export const PASSWORD_PROMPT_SEC = 300;
export const OTP_PROMPT_SEC = 120;
const OUTPUT_LIMIT = 256 * 1024;
const KOKO_READY_TIMEOUT_MS = 25_000;
/** 超时发出 KILL/close 后，再等多久仍无 close 事件就直接返回，避免调用永久挂起 */
const KILL_GRACE_MS = 5_000;
const LOGIN_KEY = 'login';

export function sha256Fingerprint(keyBuffer) {
  return createHash('sha256').update(keyBuffer).digest('base64').replace(/=+$/, '');
}

/** KoKo 令牌直连语法：JMS-<连接令牌 id>，令牌密钥当密码 */
export function tokenUsername(tokenId) {
  return `JMS-${tokenId}`;
}

const minutes = (sec) => `${Math.round(sec / 6) / 10} 分钟`.replace('.0 ', ' ');

/**
 * 登录弹窗内容：说明是谁在请求、为什么要输入、输入的内容会怎么处理、多久不输入会自动关闭。
 * 返回 { headline, detail }，输错时由弹窗把错误提示置顶。
 * @param {{user: string, host: string, ttlMs: number, step: 'password'|'otp', context?: {asset: string, account: string, privileged?: boolean}|null}} o
 */
export function loginDialog({ user, host, ttlMs, step, context = null }) {
  const hours = Math.round(ttlMs / 360_000) / 10;
  if (step === 'otp') {
    return {
      headline: '输入 MFA 动态码',
      detail: [
        '密码已通过。请输入验证器 App 里当前的动态码。',
        '安全说明：动态码只用于本次登录，不会保存，也不会交给 AI。',
        '',
        `用户：${user} · 第 2 步 / 共 2 步 · ${minutes(OTP_PROMPT_SEC)}内未输入，窗口将自动关闭`,
      ].join('\n'),
    };
  }
  const who = context ? `AI 助手请求在 ${context.asset} 上以 ${context.account}${context.privileged ? '（特权账号）' : ''} 执行命令，` : '';
  return {
    headline: '输入 JumpServer 登录密码',
    detail: [
      `${who}需要先登录 JumpServer。`,
      '',
      `用户：${user}（${host}）`,
      '为什么要输入密码：JumpServer 要先确认是你本人，才会授权 AI 连接服务器。',
      '安全说明：密码只用于这一次登录，不会保存、不写入日志，也不会交给 AI。',
      `有效期：登录后最长 ${hours} 小时，期间连接各服务器都不再需要输入。`,
      '',
      `第 1 步 / 共 2 步 · ${minutes(PASSWORD_PROMPT_SEC)}内未输入，窗口将自动关闭`,
    ].join('\n'),
  };
}

/** 登录弹窗的整段文字（标题行 + 说明，输错时带错误提示），给 pinentry 与兜底样式使用。 */
export function loginDescription(o) {
  return composeDescription({ ...loginDialog(o), error: o.error ?? null });
}

/** 登录失败时展示给用户的原因与下一步；用户主动取消不算失败，不提示。 */
export function failureMessage(e) {
  if (e.code === 'password_failed') {
    const left = e.remaining != null ? `，还剩 ${e.remaining} 次机会` : '';
    return `密码不正确${left}。请确认密码后再让 AI 重试。连续输错可能触发账号锁定，锁定时间取决于服务端策略。`;
  }
  if (/^MFA 验证失败/.test(e.message)) return '动态码验证失败。请等验证器刷新出新的动态码后，再让 AI 重试。';
  if (e.code === 'network') return '无法连接 JumpServer。请检查网络连接，并确认本机可以访问配置的 JumpServer 地址。';
  return `登录失败：${e.message}`;
}

/**
 * 在已建立的 SSH 连接上执行一条非交互命令。超时只关闭这条通道。
 * @returns {Promise<{exitCode: number|null, signal: string|null, stdout: string, stderr: string, timedOut: boolean, truncated: boolean}>}
 */
export function execOnce(client, command, timeoutMs, killGraceMs = KILL_GRACE_MS) {
  return new Promise((resolve, reject) => {
    client.exec(command, (err, stream) => {
      if (err) { reject(new Error(`打开执行通道失败: ${err.message}`)); return; }
      // 按字节收集，结束时一次性解码，避免多字节字符被分块截断成乱码
      const out = { stdout: [], stderr: [], bytes: 0 };
      let truncated = false;
      let timedOut = false;
      let done = false;
      let graceTimer = null;
      const collect = (which) => (chunk) => {
        const room = OUTPUT_LIMIT - out.bytes;
        if (room <= 0) { truncated = true; return; }
        const part = chunk.length > room ? chunk.subarray(0, room) : chunk;
        if (part.length < chunk.length) truncated = true;
        out[which].push(part);
        out.bytes += part.length;
      };
      const finish = (code, signal) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        clearTimeout(graceTimer);
        resolve({
          exitCode: code ?? null,
          signal: signal ?? null,
          stdout: Buffer.concat(out.stdout).toString('utf8'),
          stderr: Buffer.concat(out.stderr).toString('utf8'),
          timedOut,
          truncated,
        });
      };
      const timer = setTimeout(() => {
        timedOut = true;
        try { stream.signal?.('KILL'); } catch { /* KoKo 可能不支持 */ }
        try { stream.close(); } catch { /* 已关闭 */ }
        if (done) return;
        graceTimer = setTimeout(() => {
          try { stream.destroy?.(); } catch { /* 忽略 */ }
          finish(null, null);
        }, killGraceMs);
      }, timeoutMs);
      stream.on('data', collect('stdout'));
      stream.stderr.on('data', collect('stderr'));
      stream.on('close', (code, signal) => finish(code, signal));
    });
  });
}

export class SessionPool {
  /**
   * @param {ReturnType<import('./config.js').normalizeConfig>} config
   * @param {{api?: any, clientFactory?: () => any, passwordPrompt?: typeof askPassword, otpPrompt?: typeof askOtp, showError?: typeof showError, notify?: typeof notifyUser, now?: () => number, log?: (msg: string) => void, killGraceMs?: number}} [deps]
   */
  constructor(config, deps = {}) {
    this.config = config;
    this.api = deps.api ?? new JumpServerApi({ baseUrl: config.jumpserver.baseUrl });
    this.clientFactory = deps.clientFactory ?? (() => new Client());
    this.passwordPrompt = deps.passwordPrompt ?? askPassword;
    this.otpPrompt = deps.otpPrompt ?? askOtp;
    this.showError = deps.showError ?? showError;
    this.notify = deps.notify ?? notifyUser;
    this.now = deps.now ?? Date.now;
    this.log = deps.log ?? ((msg) => process.stderr.write(`[jms-mcp] ${msg}\n`));
    this.killGraceMs = deps.killGraceMs ?? KILL_GRACE_MS;
    /** 只有一项：本机共享的登录态 { token, user, readyAt, expiresAt, timer } */
    this.sessions = new Map();
    /** 进行中的登录，并发调用共用一次 */
    this.pending = new Map();
    /** 资产名 → { id, accounts: [{alias, name, username}] }，登录态失效时清空 */
    this.assetCache = new Map();
  }

  /** 取有效登录态；没有或已过期则弹窗登录（密码 + OTP）。并发调用共用同一次登录。 */
  async ensureLogin(context = null) {
    const cur = this.sessions.get(LOGIN_KEY);
    if (cur && this.now() < cur.expiresAt) return cur;
    if (cur) this.close(LOGIN_KEY, '已到有效期');
    if (!this.pending.has(LOGIN_KEY)) {
      const p = this.#login(context).finally(() => this.pending.delete(LOGIN_KEY));
      this.pending.set(LOGIN_KEY, p);
    }
    return this.pending.get(LOGIN_KEY);
  }

  /**
   * 弹窗登录：密码输错且剩余次数充足时，在弹窗里提示原因并让用户重输；其余失败弹出提示框告知用户。
   * 用户主动取消不算失败，不弹提示。
   * @param {{asset: string, account: string, privileged?: boolean}|null} context 是谁触发的登录，写进弹窗
   */
  async #login(context) {
    const { user, koko, ttlMs, pinentryPath } = this.config;
    const title = `JumpServer 登录 - ${user}`;
    const dialog = (step, error) => ({ ...loginDialog({ user, host: koko.host, ttlMs, step, context }), error, description: loginDescription({ user, host: koko.host, ttlMs, step, context, error }) });
    /** 弹窗超时时通知用户（窗口已消失，不能让人一头雾水），并给 AI 一个明确的原因 */
    const ask = async (fn, what, seconds) => {
      try {
        return await fn();
      } catch (e) {
        if (e.code !== 'prompt_timeout') throw e;
        Promise.resolve(this.notify({ title: 'JumpServer 登录窗口已超时', message: `${minutes(seconds)}内没有输入，窗口已自动关闭。需要时请让 AI 重新发起。` })).catch(() => {});
        throw Object.assign(new Error(`${what}窗口等待 ${minutes(seconds)}无人输入，已自动关闭，登录未完成`), { code: 'prompt_timeout' });
      }
    };
    const getOtp = async ({ error }) => {
      this.log(`等待人工输入 OTP: ${user}`);
      const code = await ask(() => this.otpPrompt({ title, ...dialog('otp', error), okLabel: '验证', timeoutSec: OTP_PROMPT_SEC, pinentryPath }), '动态码', OTP_PROMPT_SEC);
      if (!code) throw new Error('未输入 OTP（已取消），登录未完成');
      return code;
    };

    let res;
    let error = null;
    for (let attempt = 1; ; attempt++) {
      this.log(`等待人工输入密码: ${user}`);
      const password = await ask(() => this.passwordPrompt({ title, ...dialog('password', error), okLabel: '登录', timeoutSec: PASSWORD_PROMPT_SEC, pinentryPath }), '密码', PASSWORD_PROMPT_SEC);
      if (!password) throw new Error('未输入密码（已取消），登录未进行');
      try {
        res = await this.api.login(user, password, getOtp); // 密码只在这一次调用里使用，之后不再保留
        break;
      } catch (e) {
        const left = e.remaining;
        if (e.code === 'password_failed' && attempt < MAX_PASSWORD_ATTEMPTS && left != null && left >= MIN_REMAINING_FOR_RETRY) {
          error = `密码不正确，还剩 ${left} 次机会。请重新输入。`;
          continue;
        }
        if (e.code !== 'prompt_timeout' && !/^未输入/.test(e.message)) await this.showError({ title: `JumpServer 登录失败 - ${user}`, message: failureMessage(e), pinentryPath });
        throw e;
      }
    }

    const readyAt = this.now();
    const expiresAt = Math.min(readyAt + ttlMs, res.expiresAt ?? Infinity);
    const entry = { token: res.token, user, readyAt, expiresAt, timer: null };
    entry.timer = setTimeout(() => this.close(LOGIN_KEY, '到达有效期'), Math.max(0, expiresAt - readyAt));
    if (typeof entry.timer.unref === 'function') entry.timer.unref();
    this.sessions.set(LOGIN_KEY, entry);
    this.log(`已登录 ${user}，有效期至 ${new Date(expiresAt).toISOString()}`);
    const until = new Date(expiresAt).toLocaleString('zh-CN', { hour12: false, month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    Promise.resolve(this.notify({ title: 'JumpServer 已登录', message: `${user} 登录成功，有效期至 ${until}。期间 AI 连接各服务器不再需要输入。` })).catch(() => {});
    return entry;
  }

  /** 资产名 → { assetId, alias }：alias 是申请连接令牌时 account 要用的账号别名。 */
  async #resolve(login, asset, account) {
    let c = this.assetCache.get(asset.name);
    if (!c) {
      const id = asset.id ?? await this.api.findAssetId(login.token, asset.name);
      if (!id) throw new Error(`JumpServer 里没有授权给你的资产 ${asset.name}`);
      c = { id, accounts: await this.api.assetAccounts(login.token, id) };
      this.assetCache.set(asset.name, c);
    }
    const a = c.accounts.find((x) => x.username === account || x.name === account);
    if (!a) throw new Error(`资产 ${asset.name} 上没有授权给你的账号 ${account}，已授权: ${c.accounts.map((x) => x.username).join(', ') || '无'}`);
    return { assetId: c.id, alias: a.alias };
  }

  /** 用令牌连 KoKo。KoKo 若仍要求 MFA 说明令牌方案没生效，不回答，直接报错。 */
  #openKoko(conn) {
    const { koko } = this.config;
    const client = this.clientFactory();
    return new Promise((resolve, reject) => {
      let settled = false;
      let hostKeyOk = false;
      const fail = (err) => {
        if (settled) return;
        settled = true;
        try { client.end(); } catch { /* 已关闭 */ }
        reject(err);
      };
      client.on('keyboard-interactive', (_n, _i, _l, prompts, finish) => {
        finish((prompts ?? []).map(() => ''));
        fail(new Error('KoKo 仍要求 MFA 验证，连接令牌没有生效；请检查 JumpServer 对该资产或账号的 MFA 规则'));
      });
      client.on('ready', () => {
        if (settled) return;
        settled = true;
        resolve(client);
      });
      client.on('error', (err) => {
        let msg = err.message;
        if (!hostKeyOk) msg = `KoKo 主机指纹校验失败或无法连接: ${err.message}`;
        else if (/authentication methods failed/i.test(err.message)) msg = `KoKo 拒绝了连接令牌（已过期或已被使用）: ${err.message}`;
        fail(new Error(msg));
      });
      client.on('close', () => fail(new Error('连接在认证完成前被关闭')));
      client.connect({
        host: koko.host,
        port: koko.port,
        username: tokenUsername(conn.id),
        password: conn.value,
        tryKeyboard: true,
        readyTimeout: KOKO_READY_TIMEOUT_MS,
        hostVerifier: (hostKey) => {
          hostKeyOk = koko.hostKeySha256.includes(sha256Fingerprint(hostKey));
          if (!hostKeyOk) this.log(`拒绝未知的 KoKo 主机指纹 SHA256:${sha256Fingerprint(hostKey)}`);
          return hostKeyOk;
        },
      });
    });
  }

  /**
   * 在资产上以指定账号执行一条命令：确保登录态 → 申请一次性令牌 → 连 KoKo 执行 → 断开。
   * 登录态失效（401）时重新登录一次；账号别名过期时刷新一次资产信息。
   * @returns {Promise<Awaited<ReturnType<typeof execOnce>> & {sessionExpiresAt: number}>}
   */
  async run(asset, account, command, timeoutMs) {
    let relogged = false;
    let refreshed = false;
    for (;;) {
      const login = await this.ensureLogin({ asset: asset.name, account, privileged: asset.privilegedAccounts.includes(account) });
      let client;
      try {
        const { assetId, alias } = await this.#resolve(login, asset, account);
        const conn = await this.api.connectionToken(login.token, assetId, alias);
        client = await this.#openKoko(conn);
      } catch (e) {
        if (e.code === 'unauthorized' && !relogged) { relogged = true; this.close(LOGIN_KEY, '登录态已失效'); continue; }
        if (e.code === 'perm_account_invalid' && !refreshed) { refreshed = true; this.assetCache.delete(asset.name); continue; }
        throw e;
      }
      try {
        const r = await execOnce(client, command, timeoutMs, this.killGraceMs);
        return { ...r, sessionExpiresAt: login.expiresAt };
      } finally {
        try { client.end(); } catch { /* 已关闭 */ }
      }
    }
  }

  /** 丢弃登录态；令牌是一次性的，不需要单独吊销。 */
  close(key = LOGIN_KEY, reason = '手动注销') {
    const entry = this.sessions.get(key);
    if (!entry) return false;
    clearTimeout(entry.timer);
    this.sessions.delete(key);
    this.assetCache.clear();
    this.log(`登录态已结束 ${entry.user}: ${reason}`);
    return true;
  }

  closeAll(reason) {
    return [...this.sessions.keys()].filter((k) => this.close(k, reason)).length;
  }

  status() {
    const now = this.now();
    return [...this.sessions.values()].map((s) => ({
      asset: '*（全部已授权资产）',
      account: s.user,
      connectedAt: new Date(s.readyAt).toISOString(),
      expiresAt: new Date(s.expiresAt).toISOString(),
      remainingMinutes: Math.max(0, Math.round((s.expiresAt - now) / 60_000)),
    }));
  }
}

/** 一次 jms_exec 里登录弹窗可能占用的最长时间：密码、动态码各最多输 3 次，再留 1 分钟余量。MCP 客户端的工具超时要大于它。 */
export const LOGIN_BUDGET_MS = (MAX_PASSWORD_ATTEMPTS * PASSWORD_PROMPT_SEC + 3 * OTP_PROMPT_SEC + 60) * 1000;
