// jms-mcp：经 JumpServer KoKo 在纳管资产上执行命令的 MCP 服务（stdio）。
// 登录（密码 + MFA）由人在本机弹窗输入。默认把登录态交给常驻 broker 持有，所有 AI 会话共享，
// 有效期内连接任何资产都不再输入；JMS_MCP_MODE=inprocess 时退回进程内登录态（每个会话单独登录）。
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { configPath, loadConfig } from './config.js';
import { ensureBroker, request } from './ipc.js';
import { DEFAULT_TIMEOUT_SEC, JmsService, MAX_TIMEOUT_SEC } from './service.js';
import { LOGIN_BUDGET_MS } from './session.js';


function text(obj) {
  return { content: [{ type: 'text', text: typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2) }] };
}

function errorText(msg) {
  return { isError: true, content: [{ type: 'text', text: msg }] };
}

/** 进程内后端：连接随 MCP 进程生灭 */
export function inprocessBackend(config) {
  const svc = new JmsService(config);
  return {
    list: async () => svc.list(),
    exec: (args) => svc.exec(args),
    logout: async () => svc.logout(),
    shutdown: () => svc.pool.closeAll('MCP 进程退出'),
  };
}

/** broker 后端：每次调用前确认 broker 在跑（必要时拉起） */
export function brokerBackend({ cfgPath = configPath(), ensure = ensureBroker, call = request } = {}) {
  const ready = async () => {
    const hello = await ensure({ configPath: cfgPath });
    return hello;
  };
  return {
    list: async () => {
      const hello = await ready();
      const r = await call('list', {});
      return hello.stale ? { ...r, warning: 'broker 运行的是旧代码或旧配置；当前没有登录态（或执行 jms_logout）后会自动换新' } : r;
    },
    exec: async (args) => {
      await ready();
      return call('exec', args, { timeoutMs: (args.timeout_sec ?? DEFAULT_TIMEOUT_SEC) * 1000 + LOGIN_BUDGET_MS });
    },
    logout: async () => { await ready(); return call('logout', {}); },
    shutdown: () => {},
  };
}

export function buildServer(backend) {
  const server = new McpServer({ name: 'jms-mcp', version: '0.3.0' });

  server.registerTool('jms_list', {
    title: '列出 JumpServer 资产与授权状态',
    description: '列出可通过 JumpServer 访问的资产、可用账号，以及当前登录态（已通过 MFA）的剩余有效期。只读，不会触发登录或 MFA。',
    inputSchema: {},
  }, async () => {
    try { return text(await backend.list()); } catch (e) { return errorText(e.message); }
  });

  server.registerTool('jms_exec', {
    title: '经 JumpServer 在资产上执行命令',
    description: [
      '经 JumpServer KoKo 在指定资产上执行一条非交互 shell 命令，返回 stdout/stderr/退出码。',
      '每条命令都会被 JumpServer 审计。若本机尚无有效登录态，会在用户桌面依次弹窗要求输入 JumpServer 密码和 MFA 动态码（各最多等待 2 分钟），',
      'AI 无法也不应代为输入。登录态在本机所有 AI 会话间共享，有效期内连接任何资产、账号都不再要密码或 MFA。',
      '命令之间不保留 cwd 和环境变量；不支持 vim/top 等交互程序。',
      '默认使用非特权账号；特权账号需显式传 account 并设 privileged=true，仅在用户明确要求时使用。',
    ].join(''),
    inputSchema: {
      asset: z.string().describe('资产名，见 jms_list'),
      command: z.string().min(1).describe('要执行的 shell 命令'),
      account: z.string().optional().describe('账号名，默认用资产的非特权默认账号'),
      privileged: z.boolean().optional().describe('使用特权账号时必须为 true'),
      timeout_sec: z.number().int().min(1).max(MAX_TIMEOUT_SEC).optional().describe(`命令超时秒数，默认 ${DEFAULT_TIMEOUT_SEC}`),
    },
  }, async (args) => {
    try { return text(await backend.exec(args)); } catch (e) { return errorText(e.message); }
  });

  server.registerTool('jms_logout', {
    title: '结束 JumpServer 登录态',
    description: '结束本机的 JumpServer 登录态，对所有 AI 会话生效；之后再执行命令需要重新输入密码和 MFA。登录态到期会自动失效，不要在每个任务结束时调用，仅在用户明确要求收回授权时使用。',
    inputSchema: {},
  }, async () => {
    try { return text(await backend.logout()); } catch (e) { return errorText(e.message); }
  });

  return server;
}

export async function main() {
  const cfgPath = configPath();
  const config = loadConfig(cfgPath); // 启动即校验配置，配置错误直接报给客户端
  const backend = process.env.JMS_MCP_MODE === 'inprocess' ? inprocessBackend(config) : brokerBackend({ cfgPath });
  const server = buildServer(backend);
  const shutdown = () => { backend.shutdown(); process.exit(0); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.stdin.on('close', shutdown);
  await server.connect(new StdioServerTransport());
}
