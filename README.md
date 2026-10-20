# termcp

A local terminal MCP server for AI agents. stdio-based, zero-config, just run commands.

termcp gives any MCP-compatible AI agent (Claude, etc.) a full terminal on your machine - shell commands, file operations, background processes, search, and stateful sessions - all through the standard Model Context Protocol over stdio. No server to deploy, no tokens to manage, no cloud.

## Quick start

```bash
git clone https://github.com/dbalchunas2-pixel/termcp.git
cd termcp
npm install
npm run build
```

Add to your MCP client config (e.g. Claude Desktop):

```json
{
  "mcpServers": {
    "termcp": {
      "command": "node",
      "args": ["/path/to/termcp/dist/index.js"]
    }
  }
}
```

That's it. Your AI agent now has a terminal.

## Tools

| Tool | Description |
|---|---|
| `run_command` | Execute a shell command. Supports stdin and tmux sessions. |
| `run_sequence` | Execute multiple commands in sequence with variable capture ($PREV, $STEP{n}). |
| `read_file` | Read a file. |
| `write_file` | Write a file. Creates parent directories. |
| `list_files` | List files and directories. |
| `search_files` | Search file contents (ripgrep or grep). |
| `get_environment` | Get OS, installed tools, and disk info. |
| `get_audit_log` | Get the audit log with filtering. |
| `get_server_info` | Get version, uptime, workspace, active processes. |
| `start_process` | Start a long-running background process. |
| `poll_output` | Poll output from a background process. |
| `kill_process` | Kill a background process. |
| `create_session` | Create a stateful tmux session (persists cwd/env). |
| `destroy_session` | Kill a tmux session. |
| `read_output` | Read output from a byte offset (for truncated output). |

## Configuration

All config is via environment variables. All optional.

| Variable | Default | Description |
|---|---|---|
| `TERMCP_WORKSPACE` | `$HOME` | Root directory for file operations. |
| `MAX_TIMEOUT_MS` | `300000` | Maximum command timeout in ms. |
| `DEFAULT_TIMEOUT_MS` | `30000` | Default command timeout in ms. |
| `MAX_OUTPUT_CHUNK` | `50000` | Output chunk size before truncation. |

### Denylist

termcp ships with a configurable denylist for accident protection (not a security boundary). Create a `denylist.json` file:

```json
{
  "patterns": ["rm -rf /", "mkfs", "dd if=", "shutdown", "reboot"]
}
```

Place it in the project root, `~/.termcp/denylist.json`, or set `TERMCP_WORKSPACE` to its directory. Patterns use simple substring matching.

### Audit log

termcp maintains a durable JSONL audit log at `~/.termcp/audit.jsonl`. Every command is logged with timestamp, tool, input, exit code, and duration. Secrets are redacted at write time (API keys, Bearer tokens, password assignments).

## Requirements

- Node.js 18+
- `tmux` (optional, for `create_session`/`destroy_session` tools)
- `ripgrep` (optional, for faster `search_files`)

## License

MIT