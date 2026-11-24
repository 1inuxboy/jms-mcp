// 读取并校验 jms-mcp 配置。配置只描述“去哪、用谁”，不含任何密码、OTP 或令牌。
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const DEFAULT_CONFIG_PATH = join(homedir(), '.jms-mcp', 'config.json');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NAME_RE = /^[A-Za-z0-9._-]+$/;

function expandHome(p) {
  return p.startsWith('~') ? join(homedir(), p.slice(1)) : p;
}

/**
 * 校验并规范化配置对象；有问题时抛出列出全部错误的异常。
 * @param {any} raw
 */
export function normalizeConfig(raw) {
  const errors = [];
  const koko = raw?.koko ?? {};
  if (!koko.host) errors.push('koko.host 必填');
  const port = koko.port ?? 2222;
  if (!Number.isInteger(port) || port <= 0) errors.push('koko.port 必须是正整数');
  const fingerprints = [].concat(koko.hostKeySha256 ?? []).map((f) => String(f).replace(/^SHA256:/, '').replace(/=+$/, ''));
  if (!fingerprints.length) errors.push('koko.hostKeySha256 必填（KoKo 主机公钥 SHA256 指纹）');

  if (!raw?.user || !NAME_RE.test(raw.user)) errors.push('user 必填，且只能含字母数字和 ._-');

  const baseUrl = String(raw?.jumpserver?.baseUrl ?? `https://${koko.host}`).replace(/\/+$/, '');
  if (!/^https?:\/\/[^/\s]+$/.test(baseUrl)) errors.push('jumpserver.baseUrl 必须形如 https://host[:port]');

  // 登录态的本地上限；实际有效期取它与 JumpServer 返回的过期时间中较早者
  const ttlHours = raw?.ttlHours ?? 24;
  if (!(ttlHours > 0 && ttlHours <= 24)) errors.push('ttlHours 必须在 (0, 24] 之间');

  const assets = {};
  for (const [name, a] of Object.entries(raw?.assets ?? {})) {
    const where = `assets.${name}`;
    if (!NAME_RE.test(name)) { errors.push(`${where}: 资产名只能含字母数字和 ._-`); continue; }
    // id 可省略：省略时按资产名在你有权访问的资产里查找；写了就必须是 UUID，并会用主机名核对
    if (a?.id !== undefined && !UUID_RE.test(a.id)) errors.push(`${where}.id 必须是 JumpServer 资产 UUID，或省略`);
    const accounts = [].concat(a?.accounts ?? []);
    if (!accounts.length) errors.push(`${where}.accounts 至少列一个账号`);
    for (const acc of accounts) if (!NAME_RE.test(acc)) errors.push(`${where}.accounts 含非法账号名 ${acc}`);
    const defaultAccount = a?.defaultAccount ?? accounts[0];
    if (defaultAccount && !accounts.includes(defaultAccount)) errors.push(`${where}.defaultAccount 必须在 accounts 中`);
    const privileged = [].concat(a?.privilegedAccounts ?? []);
    for (const acc of privileged) if (!accounts.includes(acc)) errors.push(`${where}.privilegedAccounts 的 ${acc} 不在 accounts 中`);
    if (privileged.includes(defaultAccount)) errors.push(`${where}.defaultAccount 不能是特权账号`);
    assets[name] = {
      name,
      id: a?.id ? String(a.id).toLowerCase() : null,
      accounts,
      defaultAccount,
      privilegedAccounts: privileged,
      expectHostname: a?.expectHostname ?? null,
      // 远端用 coreutils timeout 包装命令，超时后由远端自己结束整个进程组（KoKo 不转发信号）
      remoteTimeout: a?.remoteTimeout !== false,
      description: a?.description ?? '',
    };
  }
  if (!Object.keys(assets).length) errors.push('assets 至少配置一个资产');

  if (errors.length) throw new Error('jms-mcp 配置无效:\n- ' + errors.join('\n- '));
  return {
    koko: { host: koko.host, port, hostKeySha256: fingerprints },
    user: raw.user,
    jumpserver: { baseUrl },
    ttlMs: Math.round(ttlHours * 3600_000),
    pinentryPath: raw.pinentryPath ?? null,
    assets,
  };
}

export function configPath(env = process.env) {
  return expandHome(env.JMS_MCP_CONFIG || DEFAULT_CONFIG_PATH);
}

export function loadConfig(path = configPath()) {
  let raw;
  try {
    raw = JSON.parse(readFileSync(expandHome(path), 'utf8'));
  } catch (e) {
    throw new Error(`读取 jms-mcp 配置失败 (${path}): ${e.message}`);
  }
  return normalizeConfig(raw);
}

/**
 * 解析要用的账号：未指定时用默认（非特权）账号；指定的账号必须在白名单里。
 * 特权账号必须显式传入，且需要 allowPrivileged=true。
 */
export function resolveAccount(asset, requested, allowPrivileged = false) {
  const account = requested || asset.defaultAccount;
  if (!asset.accounts.includes(account)) {
    throw new Error(`资产 ${asset.name} 未配置账号 ${account}，可用: ${asset.accounts.join(', ')}`);
  }
  if (asset.privilegedAccounts.includes(account) && !(requested && allowPrivileged)) {
    throw new Error(`${account} 是特权账号，必须显式指定 account 并设置 privileged=true`);
  }
  return account;
}
