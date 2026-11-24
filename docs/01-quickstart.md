# 01 快速上手

目标：在自己的电脑上装好 jms-mcp，用**自己的 JumpServer 用户**登录，并接入 Claude Code 或 Codex。

## 1. 先确认 JumpServer 侧已就绪

这几项在 JumpServer 里完成，jms-mcp 无法代办：

| 项 | 怎么确认 |
|---|---|
| 账号已绑定 MFA | 登录 JumpServer 网页，个人信息里能看到 MFA 已启用，方式是动态码（OTP） |
| 资产与账号已授权给你 | 「我的资产」里能看到目标服务器，且列出了要用的账号 |
| 网络可达 | `nc -vz jumpserver.example.com 443` 与 `nc -vz jumpserver.example.com 2222` 都能连通 |

**不需要 SSH 私钥，也不需要绑定公钥**：连接靠登录后申请的一次性令牌。

示例域名 `jumpserver.example.com` 仅用于说明。请使用管理员提供的实际地址和端口。

## 2. 安装

```bash
cd /path/to/jms-mcp
npm ci
mkdir -p ~/.jms-mcp
cp config.example.json ~/.jms-mcp/config.json
```

## 3. 改成自己的配置

编辑 `~/.jms-mcp/config.json`，**换用户就改这几项**：

| 字段 | 填什么 |
|---|---|
| `user` | 你自己的 JumpServer 用户名 |
| `assets.<名>` | 资产名，必须和 JumpServer 里的资产名一致，工具会按名称在你的授权列表里查找 |
| `assets.<名>.accounts` | 只写**已授权给你**的账号 |
| `assets.<名>.defaultAccount` | 默认账号，必须是**非特权**账号 |
| `assets.<名>.privilegedAccounts` | 特权账号（如 `admin`），AI 默认不会用，要显式指定 |
| `assets.<名>.expectHostname` | 填服务器真实主机名，每个账号首次使用前会核对，防止资产配错 |

把下表中的 KoKo 地址、端口和主机指纹设为本次部署的值。

| 字段 | 示例或默认值 | 说明 |
|---|---|---|
| `koko.host` / `koko.port` | `jumpserver.example.com` / `2222` | 填写管理员提供的 KoKo 主机名和 SSH 端口 |
| `koko.hostKeySha256` | 必填 | 通过受信渠道向管理员核实 KoKo 的 SSH 主机公钥 SHA256 指纹，再替换示例占位符。指纹不一致时会拒绝连接 |
| `ttlHours` | 24 | 登录态的本地上限，最大 24。实际有效期取它和 JumpServer 返回的过期时间中较早的 |
| `jumpserver.baseUrl` | `https://<koko.host>` | JumpServer 网页地址，API 走这里；只有地址不同时才写 |
| `assets.<名>.id` | 省略 | 资产 UUID。省略时按名称查；写了会直接使用，主机名核对能发现写错 |
| `assets.<名>.remoteTimeout` | `true` | 目标不是 Linux，或没有 `timeout`、`bash` 时才关 |

配置里**不能放**密码、动态码、令牌。旧版配置里的 `keyPath`、`keepaliveSec` 已不再使用，留着不影响。

### 添加资产

在 `assets` 下再加一项，只需要账号信息：

```json
"my-server": {
  "accounts": ["ops"],
  "defaultAccount": "ops",
  "expectHostname": "my-server",
  "description": "说明"
}
```

## 4. 接入客户端

路径写成你本机上的绝对路径。

**Claude Code**，在 `~/.claude.json` 的顶层 `mcpServers` 里加：

```json
"jms": {
  "type": "stdio",
  "command": "node",
  "args": ["/绝对路径/jms-mcp/src/cli.js"]
}
```

**Codex**，在 `~/.codex/config.toml` 里加：

```toml
[mcp_servers.jms]
command = "node"
args = ["/绝对路径/jms-mcp/src/cli.js"]
startup_timeout_sec = 20.0
tool_timeout_sec = 1500
```

**Codex 必须设置 `tool_timeout_sec`**：它默认只给每次工具调用 60 秒，而首次执行要等你在弹窗里输入密码和动态码，最长可能等好几分钟，超过 60 秒会被 Codex 直接取消。`1500`（25 分钟）刚好覆盖密码和动态码各输错重输 3 次的最长等待。Claude Code 的 MCP 工具超时默认很长，一般不用改。

改完**重启客户端**，MCP 才会加载。Windows 可使用正斜杠，例如 `C:/projects/jms-mcp/src/cli.js`。

## 5. 验证

1. 让 AI 调用 `jms_list`：应能看到你配置的资产和账号，`activeSessions` 为空，**此时不会弹窗**。
2. 让 AI 在某个资产上执行一条只读命令，例如 `hostname`：
   - 会依次弹出两个窗口，标题都是「JumpServer 登录 - 你的用户名」。先输入**登录密码**，再输入**当前的动态码**。
   - 窗口里会写明：是哪个资产、哪个账号触发了这次登录，为什么需要输入密码，以及密码只用于这一次登录、不会保存、不会交给 AI。先核对用户名是你自己、触发的操作是你预期的，再输入。
   - 密码或动态码输错时，窗口里会直接用「⚠️」提示原因和剩余次数，可以当场重输；剩余次数不多时会停下并弹出提示框，不会替你继续试，避免账号被锁。
   - 登录成功后会有一条系统通知，写明有效期。密码和动态码支持任意字符，包括引号、反斜杠、`%`、`$`、中文和空格，原样提交，不做任何转义或裁剪。
3. 返回的 `stdout` 是目标主机名，`sessionExpiresAt` 约在 24 小时之后，说明登录成功。
4. 再换一个资产或账号执行命令，**不应再弹窗**。

## 常用命令

```bash
node src/cli.js status   # 查看 broker 与登录态的剩余有效期
node src/cli.js stop     # 结束登录态并停止 broker（收回授权）
```

遇到问题看 [04-排障](04-troubleshooting.md)。

---

[← 返回目录](../README.md)
