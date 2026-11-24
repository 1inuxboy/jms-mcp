// 测试共用：假 JumpServer API、假 KoKo 客户端与连接池工厂
import { EventEmitter } from 'node:events';
import { normalizeConfig } from '../src/config.js';
import { JmsApiError } from '../src/jumpserver.js';
import { PromptTimeoutError } from '../src/prompt.js';
import { SessionPool, sha256Fingerprint } from '../src/session.js';

export const HOST_KEY = Buffer.from('fake-koko-host-key');
export const FP = sha256Fingerprint(HOST_KEY);
export const ASSET_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

export const RAW = {
  koko: { host: 'koko.test', port: 2222, hostKeySha256: `SHA256:${FP}` },
  user: 'alice',
  ttlHours: 1,
  assets: {
    'web-1': {
      id: ASSET_ID.toUpperCase(),
      accounts: ['ops', 'admin'],
      privilegedAccounts: ['admin'],
      expectHostname: 'web-1',
    },
  },
};

/**
 * 假 JumpServer API。behavior：
 *   loginExpiresAt → 登录返回的过期时间戳；unauthorizedOnce → 第一次申请令牌返回 401；tokenError → 申请令牌一律抛出该错误
 * 不保存密码内容，只记长度。
 */
export class FakeApi {
  constructor(behavior = {}) {
    this.behavior = behavior;
    this.logins = 0;
    this.assetLookups = 0;
    this.accountLookups = 0;
    this.tokens = [];
    this.unauthorizedDone = false;
  }
  async login(user, password, getOtp) {
    this.logins++;
    this.lastLogin = { user, passwordLength: password.length };
    this.passwordsSeen = [...(this.passwordsSeen ?? []), password];
    if (this.behavior.correctPassword && password !== this.behavior.correctPassword) {
      const remaining = this.behavior.remaining ?? 6;
      throw new JmsApiError(`用户名或密码错误: incorrect, You have ${remaining} more attempt(s)`, { code: 'password_failed', status: 400, remaining });
    }
    let error = null;
    for (let attempt = 1; ; attempt++) {
      const code = await getOtp({ attempt, error });
      if (code === '123456') break;
      if (attempt >= 3) throw new JmsApiError('MFA 验证失败: 动态码错误', { code: 'mfa_failed', status: 400 });
      error = '动态码不正确（动态码错误）。请等待验证器刷新出新的动态码后再输入。';
    }
    return { token: `bearer-${this.logins}`, expiresAt: this.behavior.loginExpiresAt ?? null };
  }
  async findAssetId(_token, name) {
    this.assetLookups++;
    return name === 'web-1' ? ASSET_ID : null;
  }
  async assetAccounts() {
    this.accountLookups++;
    return [
      { alias: 'alias-ops', name: 'ops', username: 'ops' },
      { alias: 'alias-admin', name: 'admin', username: 'admin' },
    ];
  }
  async connectionToken(token, assetId, alias) {
    if (this.behavior.unauthorizedOnce && !this.unauthorizedDone) {
      this.unauthorizedDone = true;
      throw new JmsApiError('JumpServer 登录态已失效', { code: 'unauthorized', status: 401 });
    }
    if (this.behavior.tokenError) throw this.behavior.tokenError;
    const n = this.tokens.length + 1;
    this.tokens.push({ token, assetId, alias });
    return { id: `tok-${n}`, value: `secret-${n}` };
  }
}

/**
 * 假 KoKo 客户端。behavior.exec(cmd) 返回值：
 *   undefined → 输出 "ran:<cmd>"；字符串/Buffer → 原样输出；数组 → 按块依次输出；
 *   'hang' → 不结束，但 close() 会结束；'stuck' → 连 close() 也不结束；'openfail' → 打不开通道
 * behavior.mfa=true 时模拟 KoKo 仍要求 MFA；behavior.hostKey 可换成别的主机公钥。
 */
export class FakeClient extends EventEmitter {
  constructor(behavior) {
    super();
    this.behavior = behavior;
    this.ended = false;
    this.execs = [];
  }
  connect(opts) {
    this.opts = opts;
    setImmediate(() => {
      if (!opts.hostVerifier(this.behavior.hostKey ?? HOST_KEY)) {
        this.emit('error', new Error('host key rejected'));
        this.emit('close');
        return;
      }
      if (this.behavior.mfa) {
        this.emit('keyboard-interactive', '', 'Please Enter MFA Code.', '', [{ prompt: '[OTP Code]: ', echo: false }], (answers) => { this.answers = answers; });
        return;
      }
      if (!opts.username.startsWith('JMS-') || !String(opts.password).startsWith('secret-')) {
        this.emit('error', new Error('All configured authentication methods failed'));
        this.emit('close');
        return;
      }
      this.emit('ready');
    });
  }
  exec(cmd, cb) {
    this.execs.push(cmd);
    const out = this.behavior.exec?.(cmd);
    if (out === 'openfail') { cb(new Error('No response from server')); return; }
    if (out === 'noopen') return; // 永远不回调，模拟 KoKo 不确认通道
    const stream = new EventEmitter();
    stream.stderr = new EventEmitter();
    stream.closed = false;
    stream.close = () => {
      if (out === 'stuck' || stream.closed) return;
      stream.closed = true;
      stream.emit('close', null, 'KILL');
    };
    stream.signal = () => {};
    stream.destroy = () => { stream.destroyed = true; };
    this.lastStream = stream;
    cb(null, stream);
    if (out === 'hang' || out === 'stuck') return;
    const fallback = cmd === 'hostname' ? 'web-1\n' : `ran:${cmd}\n`;
    const chunks = Array.isArray(out) ? out : [out ?? fallback];
    const finish = () => { stream.closed = true; stream.emit('close', this.behavior.exitCode?.(cmd) ?? 0); };
    if (this.behavior.execDelayMs) {
      setTimeout(() => { chunks.forEach((c) => stream.emit('data', Buffer.from(c))); finish(); }, this.behavior.execDelayMs);
    } else {
      setImmediate(() => { chunks.forEach((c) => stream.emit('data', Buffer.from(c))); finish(); });
    }
  }
  end() { if (!this.ended) { this.ended = true; this.emit('close'); } }
}

/** behavior.password / behavior.otp：弹窗返回值，null 表示用户取消 */
export function makePool(behavior = {}, extra = {}, rawConfig = RAW) {
  const config = normalizeConfig(rawConfig);
  const clients = [];
  const api = new FakeApi(behavior);
  let otps = 0;
  let passwords = 0;
  const prompts = { password: [], otp: [] };
  const shown = { errors: [], notices: [] }; // 测试里绝不能真的弹窗，错误提示与通知都记录下来
  const pool = new SessionPool(config, {
    api,
    clientFactory: () => { const c = new FakeClient(behavior); clients.push(c); return c; },
    passwordPrompt: async (o) => {
      passwords++;
      prompts.password.push(o);
      const v = behavior.password === undefined ? 'pw-secret-1' : behavior.password;
      if (v === 'TIMEOUT') throw new PromptTimeoutError(o.timeoutSec);
      return Array.isArray(v) ? v[Math.min(passwords - 1, v.length - 1)] : v; // 数组：按次序返回，模拟用户重输
    },
    otpPrompt: async (o) => {
      otps++;
      prompts.otp.push(o);
      const v = behavior.otp === undefined ? '123456' : behavior.otp;
      if (v === 'TIMEOUT') throw new PromptTimeoutError(o.timeoutSec);
      return Array.isArray(v) ? v[Math.min(otps - 1, v.length - 1)] : v;
    },
    showError: async (o) => { shown.errors.push(o); },
    notify: async (o) => { shown.notices.push(o); },
    log: () => {},
    ...extra,
  });
  return { pool, config, clients, api, seen: prompts, shown, prompts: () => otps, passwords: () => passwords, allExecs: () => clients.flatMap((c) => c.execs) };
}
