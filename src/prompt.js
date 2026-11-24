// 在本机桌面弹出隐藏输入框，向人索取 JumpServer 密码和 OTP。
// 密码与 OTP 只经由弹窗进程的 stdout 交给本进程，再直接发给 JumpServer：不返回给 AI、不写日志、不落盘。
//  - macOS：优先用 AppKit 的 NSAlert（经 osascript 的 JXA），有加粗标题、图标与密码框；失败时退回系统自带 display dialog
//  - Windows：Git for Windows 自带的 pinentry-w32
// 标题、正文等文字都通过参数传给弹窗进程，不拼进脚本源码，所以任意字符都不需要转义。
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';

const OTP_RE = /^[0-9]{6,8}$/;
const DEFAULT_WIN_PINENTRY = 'C:\\Program Files\\Git\\usr\\bin\\pinentry-w32.exe';
/** 默认等待时长；调用方可按步骤覆盖。弹窗到时自动关闭，并在正文里写明 */
export const DEFAULT_PROMPT_TIMEOUT_SEC = 120;

export class PromptTimeoutError extends Error {
  constructor(seconds) {
    super(`弹窗等待 ${Math.round(seconds / 60 * 10) / 10} 分钟无人操作，已自动关闭`);
    this.code = 'prompt_timeout';
  }
}

/** 从 pinentry 的 Assuan 输出中取 OTP。 */
export function parsePinentryOutput(stdout) {
  const m = /^D ([0-9]{6,8})\r?$/m.exec(stdout ?? '');
  return m ? m[1] : null;
}

/** 从 osascript 输出中取 OTP。 */
export function parseOsascriptOutput(stdout) {
  const v = String(stdout ?? '').trim();
  return OTP_RE.test(v) ? v : null;
}

/** 从 pinentry 的 Assuan 输出中取密码；数据行里 % 和换行是百分号编码的，只需还原这三种。 */
export function parsePinentryPassword(stdout) {
  const m = /^D (.+?)\r?$/m.exec(stdout ?? '');
  if (!m) return null;
  return m[1].replace(/%(25|0D|0A)/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** 从 osascript 输出中取密码：只去掉结尾的换行，不 trim，密码两端的空格也算数。 */
export function parseOsascriptPassword(stdout) {
  const v = String(stdout ?? '').replace(/\r?\n$/, '');
  return v ? v : null;
}

/** 远程会话（SSH 登录）里启动时，弹窗不会出现在人的桌面上，直接拒绝而不是卡住。 */
export function headlessReason(env = process.env, platform = process.platform) {
  if (env.JMS_MCP_ALLOW_REMOTE_PROMPT === '1') return null;
  if (env.SSH_CONNECTION || env.SSH_CLIENT || env.SSH_TTY) {
    return '当前进程运行在 SSH 远程会话中，弹窗无法显示到桌面';
  }
  if (platform !== 'darwin' && platform !== 'win32') {
    return `暂不支持 ${platform} 上的弹窗`;
  }
  return null;
}

/** 弹窗进程：返回 { ok, stdout, stderr, killed }，killed 表示到时被我们结束（即超时）。 */
function run(file, args, { input, timeoutMs }) {
  return new Promise((resolve) => {
    const child = execFile(file, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 65536, windowsHide: false },
      (err, stdout, stderr) => resolve({ ok: !err, stdout: err ? '' : stdout, stderr: String(stderr ?? ''), killed: Boolean(err?.killed) }));
    child.stdin.on('error', () => {});
    child.stdin.end(input ?? '');
  });
}

/** AppleScript 字符串字面量：转义反斜杠、双引号，换行用 \n 转义（仅用于 display dialog 兜底） */
export function escAppleScript(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r?\n/g, '\\n');
}

/** Assuan 协议参数：% 与换行需百分号编码，否则换行会截断命令 */
export function escAssuan(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/** 标题行、错误提示、说明合成一段文字，给 pinentry 与 display dialog 兜底使用。 */
export function composeDescription({ headline, detail, error }) {
  return [error ? `⚠️ ${error}` : null, error ? '' : null, headline, '', detail].filter((x) => x !== null).join('\n').trim();
}

function pinentryScript(o, mode) {
  const lines = [`SETTITLE ${escAssuan(o.title)}`, `SETDESC ${escAssuan(o.description)}`];
  if (o.timeoutSec) lines.push(`SETTIMEOUT ${Math.round(o.timeoutSec)}`);
  if (mode === 'message') lines.push(`SETOK ${escAssuan('好')}`, 'MESSAGE');
  else lines.push(`SETPROMPT ${escAssuan(o.label)}`, `SETOK ${escAssuan(o.okLabel)}`, `SETCANCEL ${escAssuan('取消')}`, 'GETPIN');
  lines.push('BYE', '');
  return lines.join('\n');
}

// AppKit 弹窗（JXA）。参数依次是：模式、标题、标题行、正文、确定按钮、是否错误态、输入框占位符。
// 输出一行 JSON：{ ok: boolean, text?: string }，ok=false 表示用户点了取消。
const JXA_ALERT = `
ObjC.import('AppKit');
function run(argv) {
  var mode = argv[0], title = argv[1], headline = argv[2], detail = argv[3], okLabel = argv[4], isError = argv[5] === '1', placeholder = argv[6];
  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
  // 弹窗进程没有菜单栏，Cmd+V/C/X/A 没人响应，密码框就无法粘贴。装一个只含编辑命令的菜单。
  var mainMenu = $.NSMenu.alloc.init;
  var editHolder = $.NSMenuItem.alloc.init;
  mainMenu.addItem(editHolder);
  var editMenu = $.NSMenu.alloc.initWithTitle('Edit');
  editMenu.addItemWithTitleActionKeyEquivalent('Cut', 'cut:', 'x');
  editMenu.addItemWithTitleActionKeyEquivalent('Copy', 'copy:', 'c');
  editMenu.addItemWithTitleActionKeyEquivalent('Paste', 'paste:', 'v');
  editMenu.addItemWithTitleActionKeyEquivalent('Select All', 'selectAll:', 'a');
  editHolder.submenu = editMenu;
  app.mainMenu = mainMenu;
  var alert = $.NSAlert.alloc.init;
  alert.messageText = headline;
  alert.informativeText = detail;
  var image = isError ? $.NSImage.imageNamed('NSCaution')
    : $.NSImage.imageWithSystemSymbolNameAccessibilityDescription(mode === 'message' ? 'exclamationmark.triangle.fill' : 'lock.shield.fill', title);
  if (image && image.isValid) alert.icon = image;
  alert.addButtonWithTitle(okLabel);
  var field = null;
  if (mode !== 'message') {
    alert.addButtonWithTitle('取消');
    field = $.NSSecureTextField.alloc.initWithFrame($.NSMakeRect(0, 0, 320, 24));
    field.placeholderString = placeholder;
    alert.accessoryView = field;
    alert.window.initialFirstResponder = field;
  }
  alert.window.title = title;
  alert.window.setLevel(3);
  app.activateIgnoringOtherApps(true);
  var resp = alert.runModal;
  if (Number(resp) !== 1000) return JSON.stringify({ ok: false });
  return JSON.stringify({ ok: true, text: field ? ObjC.unwrap(field.stringValue) : '' });
}`;

/** 弹窗结果诊断，写到 stderr（broker 会落到 broker.log）；只写结果类别与耗时，不含任何输入内容。 */
const diag = (m) => process.stderr.write(`${new Date().toISOString()} [prompt] ${m}\n`);

/** macOS：AppKit 弹窗。返回 { ok, text } 或 { failed: true }（脚本本身出错，调用方可退回兜底样式）。 */
async function alertMac({ mode, title, headline, detail, okLabel, isError, placeholder, timeoutSec }) {
  const t0 = Date.now();
  const r = await run('/usr/bin/osascript', ['-l', 'JavaScript', '-e', JXA_ALERT, mode, title, headline, detail, okLabel, isError ? '1' : '0', placeholder ?? ''], { timeoutMs: timeoutSec * 1000 });
  const ms = Date.now() - t0;
  if (r.killed) { diag(`弹窗(${mode})超时 耗时=${ms}ms`); throw new PromptTimeoutError(timeoutSec); }
  if (!r.ok) { diag(`弹窗(${mode})脚本失败 耗时=${ms}ms 原因=${r.stderr.trim().slice(0, 200)}`); return { failed: true, reason: r.stderr.trim().slice(0, 300) }; }
  try {
    const out = JSON.parse(r.stdout.trim());
    diag(`弹窗(${mode})返回 ${out.ok ? '已确认' : '已取消'} ${out.ok ? (out.text ? '内容非空' : '内容为空') : ''} 耗时=${ms}ms`); // 只记结果类别，不记内容
    return out;
  } catch { diag(`弹窗(${mode})输出无法解析 耗时=${ms}ms`); return { failed: true, reason: `无法解析弹窗输出: ${r.stdout.slice(0, 100)}` }; }
}

/** macOS 兜底：系统自带 display dialog，样式朴素但一定可用。 */
async function dialogMacFallback({ title, description, okLabel, timeoutSec, parse }) {
  const ok = escAppleScript(okLabel);
  const script = [
    `set r to display dialog "${escAppleScript(description)}" default answer "" with hidden answer with title "${escAppleScript(title)}" buttons {"取消", "${ok}"} default button "${ok}" cancel button "取消" giving up after ${timeoutSec}`,
    'if gave up of r then return "__timeout__"',
    'return text returned of r',
  ].join('\n');
  const r = await run('/usr/bin/osascript', ['-e', script], { timeoutMs: (timeoutSec + 5) * 1000 });
  if (r.killed || r.stdout.trim() === '__timeout__') throw new PromptTimeoutError(timeoutSec);
  return parse(r.stdout);
}

/**
 * 通用隐藏输入弹窗；用户取消或输入不合法时返回 null，超过 timeoutSec 无人操作抛出 PromptTimeoutError。
 * headline/detail/error 用于 AppKit 弹窗的分层排版，description 是合成后的整段文字，给 pinentry 与兜底样式用。
 */
async function askSecret({ title, headline, detail, error = null, description, pinentryPath, label, placeholder, okLabel = '确定', timeoutSec = DEFAULT_PROMPT_TIMEOUT_SEC, parseSecret }) {
  const reason = headlessReason();
  if (reason) throw new Error(reason);
  const text = description ?? composeDescription({ headline, detail, error });

  if (process.platform === 'win32' || pinentryPath) {
    const exe = pinentryPath || DEFAULT_WIN_PINENTRY;
    if (!existsSync(exe)) throw new Error(`未找到 pinentry: ${exe}（需要 Git for Windows，或在配置里设 pinentryPath）`);
    const r = await run(exe, [], { input: pinentryScript({ title, description: text, label, okLabel, timeoutSec }, 'secret'), timeoutMs: (timeoutSec + 5) * 1000 });
    if (r.killed || /ERR \d+ .*time\s*out/i.test(r.stdout)) throw new PromptTimeoutError(timeoutSec);
    return parseSecret.pinentry(r.stdout);
  }

  if (headline !== undefined) {
    const r = await alertMac({ mode: 'secret', title, headline: error ?? headline, detail: error ? `${headline}\n\n${detail}` : detail, okLabel, isError: Boolean(error), placeholder, timeoutSec });
    if (!r.failed) return r.ok ? parseSecret.text(r.text) : null;
    if (process.env.JMS_MCP_DEBUG) process.stderr.write(`[jms-mcp] AppKit 弹窗失败，退回 display dialog: ${r.reason}\n`);
  }
  return dialogMacFallback({ title, description: text, okLabel, timeoutSec, parse: parseSecret.osascript });
}

const OTP_PARSERS = { pinentry: parsePinentryOutput, osascript: parseOsascriptOutput, text: (t) => parseOsascriptOutput(t) };
const PASSWORD_PARSERS = { pinentry: parsePinentryPassword, osascript: parseOsascriptPassword, text: (t) => (t ? t : null) };

/**
 * 弹窗索取 MFA 动态码。
 * @param {{title: string, headline?: string, detail?: string, error?: string|null, description?: string, okLabel?: string, timeoutSec?: number, pinentryPath?: string|null}} opts
 */
export function askOtp(opts) {
  return askSecret({ ...opts, label: '动态码:', placeholder: '动态码', parseSecret: OTP_PARSERS });
}

/**
 * 弹窗索取 JumpServer 登录密码。
 * @param {{title: string, headline?: string, detail?: string, error?: string|null, description?: string, okLabel?: string, timeoutSec?: number, pinentryPath?: string|null}} opts
 */
export function askPassword(opts) {
  return askSecret({ ...opts, label: '密码:', placeholder: '登录密码', parseSecret: PASSWORD_PARSERS });
}

/** 登录失败时给用户一个必须看到的提示框（只有「好」一个按钮）；无法显示时静默跳过，不影响错误上报。 */
export async function showError({ title, message, pinentryPath }) {
  if (headlessReason()) return;
  try {
    if (process.platform === 'win32' || pinentryPath) {
      const exe = pinentryPath || DEFAULT_WIN_PINENTRY;
      if (!existsSync(exe)) return;
      await run(exe, [], { input: pinentryScript({ title, description: message }, 'message'), timeoutMs: 65_000 });
      return;
    }
    const r = await alertMac({ mode: 'message', title, headline: title, detail: message, okLabel: '好', isError: true, timeoutSec: 60 });
    if (r.failed) {
      await run('/usr/bin/osascript', ['-e', `display dialog "${escAppleScript(message)}" with title "${escAppleScript(title)}" buttons {"好"} default button "好" with icon caution giving up after 60`], { timeoutMs: 65_000 });
    }
  } catch { /* 提示失败不影响主流程 */ }
}

/** 非打断式通知（仅 macOS 通知中心）；失败或不支持时静默跳过。 */
export async function notifyUser({ title, message }) {
  if (process.platform !== 'darwin' || headlessReason()) return;
  try {
    await run('/usr/bin/osascript', ['-e', `display notification "${escAppleScript(message)}" with title "${escAppleScript(title)}"`], { timeoutMs: 10_000 });
  } catch { /* 通知失败不影响主流程 */ }
}
