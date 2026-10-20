#!/usr/bin/env node
// termcp - A local terminal MCP server for AI agents.
// stdio-based, zero-config. Just run commands on your machine.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec, spawn } from "child_process";
import { promisify } from "util";
import { readFile, writeFile, readdir, stat, mkdir } from "fs/promises";
import { appendFileSync, readFileSync, realpathSync } from "fs";
import { join, resolve, isAbsolute, dirname } from "path";
import { homedir } from "os";
import { z } from "zod";
import { randomUUID } from "crypto";

const execAsync = promisify(exec);

// --- Config ---
const WORKSPACE = process.env.TERMCP_WORKSPACE || homedir();
const MAX_TIMEOUT_MS = parseInt(process.env.MAX_TIMEOUT_MS || "300000", 10);
const DEFAULT_TIMEOUT_MS = parseInt(process.env.DEFAULT_TIMEOUT_MS || "30000", 10);
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_OUTPUT_CHUNK = parseInt(process.env.MAX_OUTPUT_CHUNK || "50000", 10);
const VERSION = "1.0.0";
const startTime = Date.now();

// --- Shared configurable denylist ---
// Accident protection, not a security boundary. A motivated caller can bypass any denylist.
const DEFAULT_DENYLIST = ["rm -rf /", "mkfs", "dd if=", ":(){ :|:& };:", "shutdown", "reboot", "halt", "init 0"];
let denylistPatterns: string[] = DEFAULT_DENYLIST;
let denylistSource = "embedded defaults";

function loadDenylist() {
  const candidates = [
    join(process.cwd(), "denylist.json"),
    join(dirname(process.argv[1] || __dirname), "denylist.json"),
    join(homedir(), ".termcp", "denylist.json"),
  ];
  for (const p of candidates) {
    try {
      const raw = readFileSync(p, "utf-8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.patterns)) {
        denylistPatterns = parsed.patterns;
        denylistSource = p;
        return;
      }
    } catch { /* try next */ }
  }
}
loadDenylist();

function isDenied(command: string): string | null {
  for (const pattern of denylistPatterns) {
    if (command.includes(pattern)) return `Command blocked by denylist (matched: ${pattern})`;
  }
  return null;
}

// --- Path safety ---
function safePath(inputPath: string): string {
  const resolved = isAbsolute(inputPath) ? resolve(inputPath) : resolve(join(WORKSPACE, inputPath));
  try {
    const real = realpathSync(resolved);
    return real;
  } catch {
    return resolved;
  }
}

// --- Secrets redaction ---
const SECRET_PATTERNS = [
  /sk-[a-zA-Z0-9]{20,}/g,
  /Bearer\s+[a-zA-Z0-9._\-]+/g,
  /password=\S+/gi,
  /token=\S+/gi,
  /\b[A-Z_]*TOKEN[A-Z_]*=\S+/g,
  /\b[A-Z_]*KEY[A-Z_]*=\S+/g,
];

function redactSecrets(text: string): string {
  let result = text;
  for (const pattern of SECRET_PATTERNS) result = result.replace(pattern, "[REDACTED]");
  return result;
}

// --- Durable JSONL audit log ---
interface AuditEntry {
  timestamp: string; tool: string; input: string;
  exit_code: number | null; duration_ms: number; error?: string;
}
const auditLog: AuditEntry[] = [];
const AUDIT_LOG_PATH = join(homedir(), ".termcp", "audit.jsonl");

function logCall(tool: string, input: string, exitCode: number | null, durationMs: number, error?: string) {
  const entry: AuditEntry = {
    timestamp: new Date().toISOString(), tool,
    input: redactSecrets(input), exit_code: exitCode, duration_ms: durationMs,
    error: error ? redactSecrets(error) : undefined,
  };
  auditLog.push(entry);
  if (auditLog.length > 200) auditLog.shift();
  try { appendFileSync(AUDIT_LOG_PATH, JSON.stringify(entry) + "\n"); } catch {}
}

// --- Background process manager ---
interface ProcessHandle {
  process_id: string; pid: number; command: string; cwd: string;
  stdout: string; stderr: string; running: boolean; exit_code: number | null;
  spawned: any; cleanTimer: any;
}
const processes = new Map<string, ProcessHandle>();

function startBgProcess(command: string, cwd: string, env: Record<string, string>): { process_id: string; pid: number } {
  const process_id = randomUUID();
  const child = spawn(command, { cwd, env: { ...process.env, ...env }, shell: true });
  const handle: ProcessHandle = {
    process_id, pid: child.pid || -1, command, cwd,
    stdout: "", stderr: "", running: true, exit_code: null,
    spawned: child, cleanTimer: null,
  };
  const MAX_BUF = 1024 * 1024;
  child.stdout?.on("data", (d: Buffer) => { handle.stdout += d.toString(); if (handle.stdout.length > MAX_BUF) handle.stdout = handle.stdout.slice(-MAX_BUF); });
  child.stderr?.on("data", (d: Buffer) => { handle.stderr += d.toString(); if (handle.stderr.length > MAX_BUF) handle.stderr = handle.stderr.slice(-MAX_BUF); });
  child.on("exit", (code: number | null) => {
    handle.running = false; handle.exit_code = code;
    handle.cleanTimer = setTimeout(() => processes.delete(process_id), 5 * 60 * 1000);
  });
  processes.set(process_id, handle);
  return { process_id, pid: child.pid || -1 };
}

// --- tmux sessions ---
const tmuxSessions = new Map<string, { session_id: string; lastActivity: number }>();
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

// --- Output chunking ---
function chunkOutput(text: string): string {
  if (text.length > MAX_OUTPUT_CHUNK) {
    return text.slice(0, MAX_OUTPUT_CHUNK) + `\n[output truncated at ${MAX_OUTPUT_CHUNK} bytes. Call read_output with offset=${MAX_OUTPUT_CHUNK} to continue]`;
  }
  return text;
}

// --- Server ---
const server = new McpServer({ name: "termcp", version: VERSION });

server.tool("run_command", "Execute a shell command locally. Returns stdout, stderr, and exit code.", {
  command: z.string().describe("The shell command to execute"),
  timeout_ms: z.number().optional().describe(`Timeout in ms (default ${DEFAULT_TIMEOUT_MS}, max ${MAX_TIMEOUT_MS})`),
  cwd: z.string().optional().describe("Working directory (default: home)"),
  stdin: z.string().optional().describe("Optional string to pipe to command stdin"),
  session_id: z.string().optional().describe("If provided, run inside this tmux session"),
}, async (args) => {
  const command = args.command;
  const timeout = Math.min(args.timeout_ms || DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const cwd = args.cwd ? safePath(args.cwd) : WORKSPACE;

  const blocked = isDenied(command);
  if (blocked) { logCall("run_command", command, null, 0, blocked); return { content: [{ type: "text", text: `BLOCKED: ${blocked}` }] }; }

  if (args.session_id && tmuxSessions.has(args.session_id)) {
    const sess = tmuxSessions.get(args.session_id)!;
    sess.lastActivity = Date.now();
    try {
      await execAsync(`tmux send-keys -t ${args.session_id} '${command.replace(/'/g, "'\\\\''")}' Enter`);
      await new Promise(r => setTimeout(r, Math.min(timeout, 5000)));
      const { stdout } = await execAsync(`tmux capture-pane -t ${args.session_id} -p -S -1000`, { timeout: 5000 });
      logCall("run_command", command, 0, 0);
      return { content: [{ type: "text", text: `[session:${args.session_id}]\n${chunkOutput(stdout)}` }] };
    } catch (err: any) {
      logCall("run_command", command, err.code ?? -1, 0, err.message);
      return { content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }

  const start = Date.now();
  try {
    let stdout: string, stderr: string;
    if (args.stdin) {
      const result = await execAsync(`echo '${args.stdin.replace(/'/g, "'\\\\''")}' | ${command}`, { cwd, timeout, maxBuffer: 5 * 1024 * 1024 });
      stdout = String(result.stdout); stderr = String(result.stderr);
    } else {
      const result = await execAsync(command, { cwd, timeout, maxBuffer: 5 * 1024 * 1024 });
      stdout = String(result.stdout); stderr = String(result.stderr);
    }
    const durationMs = Date.now() - start;
    logCall("run_command", command, 0, durationMs);
    let output = "";
    if (stdout) output += stdout;
    if (stderr) output += (output ? "\n--- stderr ---\n" : "") + stderr;
    if (!output) output = "(no output)";
    return { content: [{ type: "text", text: `exit_code: 0\ntime: ${durationMs}ms\n\n${chunkOutput(output)}` }] };
  } catch (err: any) {
    const durationMs = Date.now() - start;
    const exitCode = err.code ?? -1;
    let output = err.stdout || "";
    if (err.stderr) output += (output ? "\n--- stderr ---\n" : "") + err.stderr;
    if (err.killed) output += (output ? "\n" : "") + `[TIMEOUT after ${timeout}ms]`;
    if (!output) output = err.message;
    logCall("run_command", command, exitCode, durationMs, err.killed ? `Timeout after ${timeout}ms` : output.slice(0, 200));
    return { content: [{ type: "text", text: `exit_code: ${exitCode}\ntime: ${durationMs}ms\n\n${chunkOutput(output)}` }] };
  }
});

server.tool("run_sequence", "Execute multiple shell commands in sequence. Supports variable capture ($PREV, $STEP{n}).", {
  commands: z.array(z.string()).describe("List of commands to execute in order"),
  stop_on_error: z.boolean().optional().describe("If true (default), stops when a command fails."),
  timeout_ms: z.number().optional().describe(`Per-command timeout in ms (default ${DEFAULT_TIMEOUT_MS})`),
  cwd: z.string().optional().describe("Working directory (default: home)"),
}, async (args) => {
  const timeout = Math.min(args.timeout_ms || DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const cwd = args.cwd ? safePath(args.cwd) : WORKSPACE;
  const stopOnError = args.stop_on_error !== false;
  const results: Array<{ command: string; exitCode: number; stdout: string; stderr: string; durationMs: number }> = [];

  for (let i = 0; i < args.commands.length; i++) {
    let command = args.commands[i];
    if (i > 0) {
      const prev = results[i - 1];
      command = command.replace(/\$PREV\.stdout/g, prev.stdout).replace(/\$PREV\.stderr/g, prev.stderr).replace(/\$PREV\.exit_code/g, String(prev.exitCode));
    }
    for (let j = 0; j < i; j++) {
      const s = results[j];
      command = command.replace(new RegExp(`\\$STEP${j + 1}\\.stdout`, "g"), s.stdout).replace(new RegExp(`\\$STEP${j + 1}\\.stderr`, "g"), s.stderr).replace(new RegExp(`\\$STEP${j + 1}\\.exit_code`, "g"), String(s.exitCode));
    }
    const blocked = isDenied(command);
    if (blocked) { results.push({ command, exitCode: -1, stdout: "", stderr: `BLOCKED: ${blocked}`, durationMs: 0 }); if (stopOnError) break; continue; }
    const start = Date.now();
    try {
      const { stdout, stderr } = await execAsync(command, { cwd, timeout, maxBuffer: 5 * 1024 * 1024 });
      results.push({ command, exitCode: 0, stdout, stderr, durationMs: Date.now() - start });
    } catch (err: any) {
      results.push({ command, exitCode: err.code ?? -1, stdout: err.stdout || "", stderr: err.stderr || err.message, durationMs: Date.now() - start });
      if (stopOnError) break;
    }
  }
  const text = results.map((r, i) => {
    let block = `[${i + 1}/${results.length}] $ ${r.command}\nexit_code: ${r.exitCode} | time: ${r.durationMs}ms\n`;
    if (r.stdout) block += r.stdout;
    if (r.stderr) block += (r.stdout ? "\n--- stderr ---\n" : "") + r.stderr;
    if (!r.stdout && !r.stderr) block += "(no output)";
    return block;
  }).join("\n\n");
  return { content: [{ type: "text", text: chunkOutput(text) }] };
});

server.tool("read_file", "Read the contents of a text file.", {
  path: z.string().describe("File path (relative to home or absolute)"),
}, async (args) => {
  try {
    const filePath = safePath(args.path);
    const content = await readFile(filePath, "utf-8");
    const result = content.length > MAX_FILE_BYTES ? content.slice(0, MAX_FILE_BYTES) + "\n[... truncated]" : content;
    return { content: [{ type: "text", text: result }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

server.tool("write_file", "Write content to a file. Creates parent directories if needed.", {
  path: z.string().describe("File path (relative to home or absolute)"),
  content: z.string().describe("The content to write"),
  append: z.boolean().optional().describe("If true, append instead of overwrite (default: false)"),
}, async (args) => {
  try {
    if (args.content.length > MAX_FILE_BYTES) throw new Error(`Content exceeds max size of ${MAX_FILE_BYTES} bytes`);
    const filePath = safePath(args.path);
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, args.content, { flag: args.append ? "a" : "w" });
    return { content: [{ type: "text", text: `Written ${args.content.length} bytes to ${filePath}` }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

server.tool("list_files", "List files and directories in a path.", {
  path: z.string().optional().describe("Directory path (default: home)"),
}, async (args) => {
  try {
    const dirPath = safePath(args.path || ".");
    const entries = await readdir(dirPath, { withFileTypes: true });
    const lines = await Promise.all(entries.map(async (entry) => {
      let size = ""; let suffix = "";
      if (entry.isFile()) { try { const s = await stat(join(dirPath, entry.name)); size = ` (${s.size} bytes)`; } catch {} }
      else if (entry.isDirectory()) suffix = "/";
      else if (entry.isSymbolicLink()) suffix = " ->";
      return `${entry.name}${suffix}${size}`;
    }));
    return { content: [{ type: "text", text: lines.length ? lines.join("\n") : "(empty directory)" }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

server.tool("search_files", "Search for a pattern in files. Uses ripgrep if available, falls back to grep.", {
  pattern: z.string().describe("Regex pattern to search for"),
  path: z.string().optional().describe("Directory to search (default: home)"),
  glob: z.string().optional().describe("File type filter (e.g. *.ts)"),
}, async (args) => {
  try {
    const searchPath = safePath(args.path || ".");
    const globFlag = args.glob ? ` --glob '${args.glob}'` : "";
    let cmd: string;
    try {
      await execAsync("which rg", { timeout: 5000 });
      cmd = `rg -n --max-count 100 ${globFlag} '${args.pattern.replace(/'/g, "'\\\\''")}' ${searchPath}`;
    } catch {
      cmd = `grep -rn --include='${args.glob || "*"}' '${args.pattern.replace(/'/g, "'\\\\''")}' ${searchPath} | head -100`;
    }
    const { stdout } = await execAsync(cmd, { timeout: 30000, maxBuffer: 5 * 1024 * 1024 });
    return { content: [{ type: "text", text: chunkOutput(stdout) || "No matches found" }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: err.stdout || "No matches found" }] };
  }
});

server.tool("get_environment", "Get info about the local environment: OS, installed tools, disk usage.", {}, async () => {
  const { stdout: osInfo } = await execAsync("uname -a", { timeout: 5000 });
  const { stdout: nodeVer } = await execAsync("node --version 2>/dev/null || echo 'not installed'", { timeout: 5000 });
  const { stdout: pyVer } = await execAsync("python3 --version 2>/dev/null || echo 'not installed'", { timeout: 5000 });
  const { stdout: gitVer } = await execAsync("git --version 2>/dev/null || echo 'not installed'", { timeout: 5000 });
  const { stdout: tmuxVer } = await execAsync("tmux -V 2>/dev/null || echo 'not installed'", { timeout: 5000 });
  return { content: [{ type: "text", text: [
    `OS: ${osInfo.trim()}`, `Workspace: ${WORKSPACE}`,
    ``, `Installed tools:`,
    `  node: ${nodeVer.trim()}`, `  python3: ${pyVer.trim()}`, `  git: ${gitVer.trim()}`, `  tmux: ${tmuxVer.trim()}`,
  ].join("\n") }] };
});

server.tool("get_audit_log", "Get the audit log of commands executed. Supports filtering.", {
  count: z.number().optional().describe("Number of entries (default: 50, max: 200)"),
  tool: z.string().optional().describe("Filter by tool name"),
  since: z.string().optional().describe("ISO timestamp - only entries after this"),
}, async (args) => {
  const limit = Math.min(args.count || 50, 200);
  let entries = auditLog.slice();
  if (args.tool) entries = entries.filter(e => e.tool === args.tool);
  if (args.since) entries = entries.filter(e => e.timestamp > args.since!);
  entries = entries.slice(-limit);
  const text = entries.length ? entries.map(e => `[${e.timestamp}] ${e.tool} | exit=${e.exit_code} | ${e.duration_ms}ms | ${e.input.slice(0, 100)}${e.error ? ` | ERROR: ${e.error.slice(0, 80)}` : ""}`).join("\n") : "(audit log is empty)";
  return { content: [{ type: "text", text }] };
});

server.tool("start_process", "Start a long-running background process. Returns process_id and pid.", {
  command: z.string().describe("The shell command to start"),
  cwd: z.string().optional().describe("Working directory (default: home)"),
  env: z.record(z.string()).optional().describe("Additional environment variables"),
}, async (args) => {
  const blocked = isDenied(args.command);
  if (blocked) return { content: [{ type: "text", text: `BLOCKED: ${blocked}` }] };
  const cwd = args.cwd ? safePath(args.cwd) : WORKSPACE;
  const { process_id, pid } = startBgProcess(args.command, cwd, args.env || {});
  return { content: [{ type: "text", text: `process_id: ${process_id}\npid: ${pid}` }] };
});

server.tool("poll_output", "Poll output from a background process.", {
  process_id: z.string().describe("The process_id from start_process"),
  since: z.number().optional().describe("Byte offset to start reading from (default: 0)"),
}, async (args) => {
  const handle = processes.get(args.process_id);
  if (!handle) return { content: [{ type: "text", text: `Error: process ${args.process_id} not found` }] };
  const offset = args.since || 0;
  const newOut = handle.stdout.slice(offset);
  const newErr = handle.stderr.slice(offset);
  return { content: [{ type: "text", text: `running: ${handle.running}\nexit_code: ${handle.exit_code}\nstdout_offset: ${handle.stdout.length}\nstderr_offset: ${handle.stderr.length}\n\n${chunkOutput(newOut + (newErr ? "\n--- stderr ---\n" + newErr : ""))}` }] };
});

server.tool("kill_process", "Kill a background process by process_id.", {
  process_id: z.string().describe("The process_id from start_process"),
  signal: z.string().optional().describe("Signal to send (default: SIGTERM)"),
}, async (args) => {
  const handle = processes.get(args.process_id);
  if (!handle) return { content: [{ type: "text", text: `Error: process ${args.process_id} not found` }] };
  try {
    handle.spawned.kill(args.signal || "SIGTERM" as any);
    return { content: [{ type: "text", text: `Killed process ${args.process_id} (pid ${handle.pid}) with ${args.signal || "SIGTERM"}` }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

server.tool("create_session", "Create a stateful tmux session with persistent cwd and environment.", {
  cwd: z.string().optional().describe("Starting working directory (default: home)"),
}, async (args) => {
  try {
    const session_id = "termcp-" + randomUUID().slice(0, 8);
    const cwd = args.cwd ? safePath(args.cwd) : WORKSPACE;
    await execAsync(`tmux new-session -d -s ${session_id} -c ${cwd}`, { timeout: 5000 });
    tmuxSessions.set(session_id, { session_id, lastActivity: Date.now() });
    return { content: [{ type: "text", text: `session_id: ${session_id}` }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

server.tool("destroy_session", "Kill a tmux session.", {
  session_id: z.string().describe("The session_id from create_session"),
}, async (args) => {
  try {
    await execAsync(`tmux kill-session -t ${args.session_id}`, { timeout: 5000 });
    tmuxSessions.delete(args.session_id);
    return { content: [{ type: "text", text: `Session ${args.session_id} destroyed` }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

server.tool("read_output", "Read output from a specific byte offset. Used for truncated output.", {
  process_id: z.string().optional().describe("Background process_id"),
  offset: z.number().optional().describe("Byte offset to start reading from (default: 0)"),
}, async (args) => {
  const handle = args.process_id ? processes.get(args.process_id) : null;
  if (!handle) return { content: [{ type: "text", text: `Error: process not found` }] };
  const offset = args.offset || 0;
  const output = (handle.stdout + handle.stderr).slice(offset, offset + MAX_OUTPUT_CHUNK);
  const hasMore = (handle.stdout.length + handle.stderr.length) > offset + MAX_OUTPUT_CHUNK;
  return { content: [{ type: "text", text: `offset: ${offset}\n${output}${hasMore ? `\n[more available, call read_output with offset=${offset + MAX_OUTPUT_CHUNK}]` : ""}` }] };
});

server.tool("get_server_info", "Get server info: version, uptime, workspace, active processes.", {}, async () => {
  return { content: [{ type: "text", text: [
    `termcp v${VERSION}`,
    `uptime_seconds: ${Math.floor((Date.now() - startTime) / 1000)}`,
    `workspace: ${WORKSPACE}`,
    `active_processes: ${processes.size}`,
    `tmux_sessions: ${tmuxSessions.size}`,
    `denylist_source: ${denylistSource}`,
    `denylist_patterns: ${denylistPatterns.length}`,
    `audit_log: ${AUDIT_LOG_PATH}`,
  ].join("\n") }] };
});

// --- Session cleanup (30 min inactivity) ---
setInterval(() => {
  const now = Date.now();
  for (const [sid, sess] of tmuxSessions) {
    if (now - sess.lastActivity > SESSION_TIMEOUT_MS) {
      execAsync(`tmux kill-session -t ${sid} 2>/dev/null`).catch(() => {});
      tmuxSessions.delete(sid);
    }
  }
}, 60000);

// --- Start ---
const transport = new StdioServerTransport();
await server.connect(transport);
