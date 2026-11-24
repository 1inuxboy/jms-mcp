// JumpServer API 客户端：登录（密码 + OTP，只此一次）、查询授权资产与账号、申请一次性连接令牌。
// 密码与 OTP 只作为参数传入、只发往 JumpServer，不记录、不返回给调用方；错误信息只含服务端的 msg。

const API_TIMEOUT_MS = 20_000;
const AUTH_PATH = '/api/v1/authentication/auth/';
const MFA_CHALLENGE_PATH = '/api/v1/authentication/mfa/challenge/';
const CONNECTION_TOKEN_PATH = '/api/v1/authentication/connection-token/';

/** 同一次登录里动态码最多输几次，避免连续输错触发 JumpServer 的锁定 */
const MAX_OTP_ATTEMPTS = 3;

export class JmsApiError extends Error {
  /** remaining：服务端提示的剩余尝试次数（密码输错时），未知为 null */
  constructor(message, { code = null, status = null, remaining = null } = {}) {
    super(message);
    this.code = code;
    this.status = status;
    this.remaining = remaining;
  }
}

/** 从 "You have 7 more attempt(s)" 里取剩余尝试次数；取不到返回 null。 */
export function remainingAttempts(msg) {
  const m = /(\d+)\s+more\s+attempt/i.exec(String(msg ?? ''));
  return m ? Number(m[1]) : null;
}

/** "2026/11/24 11:03:35 +0800" → 毫秒时间戳；解析不了返回 null（调用方回退到本地有效期）。 */
export function parseJmsDate(s) {
  const m = /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2}) ([+-]\d{2})(\d{2})$/.exec(String(s ?? '').trim());
  if (!m) return null;
  const t = Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7]}:${m[8]}`);
  return Number.isNaN(t) ? null : t;
}

function serverMessage(r) {
  const d = r.data;
  return String(d?.msg ?? d?.detail ?? d?.error ?? `HTTP ${r.status}`).slice(0, 300);
}

/** 服务端的错误码：有的接口放在 code，有的（如登录要求 MFA）放在 error，两处都认。 */
function respCode(d) {
  return d?.code ?? d?.error ?? null;
}

export class JumpServerApi {
  /** @param {{baseUrl: string, fetchImpl?: typeof fetch}} opts */
  constructor({ baseUrl, fetchImpl = globalThis.fetch }) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.fetch = fetchImpl;
  }

  async #req(method, path, { body, token, jar } = {}) {
    const headers = { 'content-type': 'application/json', accept: 'application/json' };
    if (jar?.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    if (jar?.has('csrftoken')) headers['x-csrftoken'] = jar.get('csrftoken');
    if (token) headers.authorization = `Bearer ${token}`;
    let res;
    try {
      res = await this.fetch(this.baseUrl + path, {
        method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(API_TIMEOUT_MS),
      });
    } catch (e) {
      throw new JmsApiError(`无法连接 JumpServer ${this.baseUrl}: ${e.cause?.code ?? e.message}`, { code: 'network' });
    }
    if (jar) {
      for (const c of res.headers.getSetCookie?.() ?? []) {
        const [kv] = c.split(';');
        const i = kv.indexOf('=');
        jar.set(kv.slice(0, i), kv.slice(i + 1));
      }
    }
    let data = null;
    try { data = await res.json(); } catch { /* 非 JSON 响应 */ }
    return { status: res.status, data };
  }

  /** 非 2xx 统一转成带 code 的异常；401 标为 unauthorized，由上层决定是否重新登录。 */
  #check(r, what) {
    if (r.status >= 200 && r.status < 300) return r.data;
    if (r.status === 401) throw new JmsApiError('JumpServer 登录态已失效', { code: 'unauthorized', status: 401 });
    throw new JmsApiError(`${what}: ${serverMessage(r)}`, { code: respCode(r.data), status: r.status });
  }

  /**
   * 密码 + OTP 登录，返回 { token, expiresAt }。getOtp 仅在服务端要求 MFA 时调用；
   * 动态码输错时（HTTP 400）最多重输 3 次，重输时 getOtp 会带上上一次的错误提示。
   * 密码经 JSON 序列化原样发送，特殊字符（引号、反斜杠、%、$、中文等）不做任何转义或裁剪。
   * @param {string} username
   * @param {string} password
   * @param {(ctx: {attempt: number, error: string|null}) => Promise<string>} getOtp
   */
  async login(username, password, getOtp) {
    const jar = new Map();
    const body = { username, password };
    let r = await this.#req('POST', AUTH_PATH, { body, jar });
    if (!r.data?.token && respCode(r.data) === 'mfa_required') {
      const info = r.data?.data ?? {};
      if (info.choices && !info.choices.includes('otp')) {
        throw new JmsApiError(`该账号的 MFA 方式（${info.choices.join(',')}）暂不支持，需要动态码（OTP）`, { code: 'mfa_unsupported' });
      }
      let error = null;
      for (let attempt = 1; ; attempt++) {
        const code = await getOtp({ attempt, error });
        const ch = await this.#req('POST', info.url ?? MFA_CHALLENGE_PATH, { body: { type: 'otp', code }, jar });
        if (ch.status >= 200 && ch.status < 300) break;
        const msg = serverMessage(ch);
        const err = new JmsApiError(`MFA 验证失败: ${msg}`, { code: respCode(ch.data) ?? 'mfa_failed', status: ch.status });
        if (ch.status !== 400 || attempt >= MAX_OTP_ATTEMPTS) throw err;
        error = `动态码不正确（${msg}）。请等待验证器刷新出新的动态码后再输入。`;
      }
      r = await this.#req('POST', AUTH_PATH, { body, jar });
    }
    if (!r.data?.token) {
      const code = respCode(r.data);
      const what = code === 'password_failed' ? '用户名或密码错误' : '登录失败';
      const msg = serverMessage(r);
      throw new JmsApiError(`${what}: ${msg}`, { code, status: r.status, remaining: remainingAttempts(msg) });
    }
    return { token: r.data.token, expiresAt: parseJmsDate(r.data.date_expired) };
  }

  /** 本人有权访问的资产里按名称找 id；找不到返回 null。 */
  async findAssetId(token, name) {
    const r = await this.#req('GET', `/api/v1/perms/users/self/assets/?limit=100&search=${encodeURIComponent(name)}`, { token });
    const data = this.#check(r, '查询资产失败');
    const list = data?.results ?? data ?? [];
    return list.find((a) => a.name === name)?.id ?? null;
  }

  /** 资产上授权给本人的账号：[{ alias, name, username }]。申请令牌时 account 要用 alias。 */
  async assetAccounts(token, assetId) {
    const r = await this.#req('GET', `/api/v1/perms/users/self/assets/${encodeURIComponent(assetId)}/`, { token });
    const data = this.#check(r, '查询资产账号失败');
    return (data?.permed_accounts ?? []).map((a) => ({ alias: a.alias, name: a.name, username: a.username }));
  }

  /** 申请一次性连接令牌（不需要再次 MFA）；返回 { id, value }，value 是令牌密钥，只用于连 KoKo。 */
  async connectionToken(token, assetId, accountAlias) {
    const r = await this.#req('POST', CONNECTION_TOKEN_PATH, {
      token,
      body: { asset: assetId, account: accountAlias, protocol: 'ssh', connect_method: 'ssh_client', input_username: '', input_secret: '', connect_options: {} },
    });
    const d = this.#check(r, '申请连接令牌失败');
    if (!d?.id || !d?.value) throw new JmsApiError('申请连接令牌失败: 响应缺少 id 或 value', { code: 'bad_response' });
    return { id: d.id, value: d.value };
  }
}
