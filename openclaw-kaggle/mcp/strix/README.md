# strix-mcp

A Model Context Protocol (stdio) server that wraps the **Strix** CLI so any MCP
host — OpenCode, Claude Desktop, etc. — can run and monitor Strix penetration
tests as native tools.

Strix ships as an MCP *client* only (it connects out to MCP servers). This
bridge is the other direction: it lets a host drive Strix.

Everything is a thin wrapper. All real work is done by the `strix` binary; this
process builds argv, supervises the subprocess, and reads the run artifacts
Strix writes under `<cwd>/strix_runs/<run_name>/`.

## Layout

```
~/.config/opencode/mcp/strix-mcp/
  server.py        # the MCP server
  .venv/           # isolated env with mcp==2.3.0
  README.md
```

Runtime state:

```
~/.local/share/strix-mcp/
  logs/<job_id>.log   # combined stdout/stderr per scan job
  jobs.json           # job index (survives restarts)
  work/               # default cwd; scans land in work/strix_runs/
```

## Tools

| Tool | What it does |
| --- | --- |
| `strix_version` | Installed Strix version + resolved path |
| `strix_start_scan` | Launch a scan in the background, return a job id immediately |
| `strix_scan` | Launch a scan and wait up to `wait_seconds` for a bounded result |
| `strix_job_status` | State, exit code, run name, log tail for a job |
| `strix_job_log` | Last N lines of a job's log |
| `strix_job_stop` | SIGTERM → SIGKILL a running job |
| `strix_jobs` | Every job this server knows about |
| `strix_list_runs` | Runs under `<cwd>/strix_runs` (status, findings count) |
| `strix_run_report` | The run's `penetration_test_report.md` |
| `strix_run_findings` | The run's `vulnerabilities.json` |

Resources: `strix://jobs`, `strix://runs`. Prompt: `pentest`.

Scans run non-interactively (`--non-interactive`); the TUI is never used.

## Typical flow

```text
strix_start_scan(targets=["https://app.example.com"], instruction="Focus on IDOR and auth", scan_mode="standard")
  -> {"job_id": "abc123", ...}
strix_job_status("abc123")     # poll until status is completed/failed
strix_run_report(run_name="...")   # read the report
```

For CI-style bounded runs use `strix_scan` with `wait_seconds` and `fail_on`.

## Environment

| Var | Default | Meaning |
| --- | --- | --- |
| `STRIX_BIN` | auto-resolved | Path to the `strix` executable |
| `STRIX_MCP_WORK` | `~/.local/share/strix-mcp/work` | Default scan working directory |
| `STRIX_MCP_DATA` | `~/.local/share/strix-mcp` | Logs + job index root |

Strix needs its own LLM/cloud credentials configured (its usual `~/.strix/`
config or environment). Those are inherited by spawned scans.

## OpenCode registration

Written to `~/.config/opencode/opencode.json` under `mcp.servers.strix`:

```jsonc
"strix": {
  "type": "local",
  "command": [
    "/home/kali/.config/opencode/mcp/strix-mcp/.venv/bin/python",
    "/home/kali/.config/opencode/mcp/strix-mcp/server.py"
  ],
  "environment": { "STRIX_BIN": "/home/kali/.local/bin/strix" }
}
```

Verify:

```sh
opencode mcp list          # -> ✓ strix  connected
```

Re-add or remove:

```sh
opencode mcp add strix --global --env STRIX_BIN=/home/kali/.local/bin/strix -- \
  /home/kali/.config/opencode/mcp/strix-mcp/.venv/bin/python \
  /home/kali/.config/opencode/mcp/strix-mcp/server.py
```

(To remove, delete the `strix` entry from `mcp.servers` in the config.)

## Notes / gotchas

- Strix spawns Docker sandbox containers. `strix_job_stop` kills the Strix
  process group; if a scan was mid-sandbox, check for stray containers
  (`docker ps`) and clean up.
- Long scans: prefer `strix_start_scan` + polling so the host call returns
  immediately.
- The server supports both `mcp` 2.x (`MCPServer`) and 1.x (`FastMCP`).

## Manual run / test

```sh
cd ~/.config/opencode/mcp/strix-mcp
.venv/bin/python server.py --selftest   # spawns a throwaway process, checks wiring
```

Speak raw MCP over stdio to poke at it:

```sh
.venv/bin/python server.py               # then send initialize / tools/list on stdin
```
