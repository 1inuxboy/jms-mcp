#!/usr/bin/env node
// 用法：
//   jms-mcp            以 stdio 方式运行 MCP 服务（供 Claude Code / Codex 启动）
//   jms-mcp broker     运行常驻 broker（一般由 MCP 自动拉起，无需手动执行）
//   jms-mcp status     查看 broker 与当前已授权连接
//   jms-mcp stop       断开全部连接并停止 broker
const cmd = process.argv[2];

async function run() {
  if (!cmd) {
    const { main } = await import('./index.js');
    return main();
  }
  if (cmd === 'broker') {
    const { runBroker } = await import('./broker.js');
    return runBroker();
  }
  if (cmd === 'status' || cmd === 'stop') {
    const { request } = await import('./ipc.js');
    try {
      const r = await request(cmd === 'status' ? 'list' : 'shutdown');
      process.stdout.write(JSON.stringify(r, null, 2) + '\n');
    } catch (e) {
      if (['ENOENT', 'ECONNREFUSED'].includes(e.code)) process.stdout.write('broker 未运行\n');
      else throw e;
    }
    return;
  }
  throw new Error(`未知子命令 ${cmd}`);
}

run().catch((e) => {
  process.stderr.write(`[jms-mcp] ${e.message}\n`);
  process.exit(1);
});
