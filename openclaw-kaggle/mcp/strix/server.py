#!/usr/bin/env python3
"""strix-mcp — a Model Context Protocol (stdio) server that wraps the Strix CLI.

Exposes Strix penetration-testing runs to any MCP host (OpenCode, Claude, etc.)
as tools: start scans, watch them, read the reports they produce.

Everything is a thin, honest wrapper around `strix`. All real work is done by
the Strix CLI; this process only builds argv, supervises the subprocess, and
reads the run artifacts Strix writes under <cwd>/strix_runs/<run_name>/.

Transport: stdio. Run it directly or let OpenCode spawn it.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

# mcp >= 2.x renamed FastMCP -> MCPServer. Fall back to the 1.x class so the
# server keeps working under either SDK generation.
try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _Server

    _MCP_API = 2
except ImportError:  # mcp < 2.0
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

    _MCP_API = 1

SERVER_NAME = "strix"
SERVER_VERSION = "1.0.0"

DATA_DIR = Path(os.environ.get("STRIX_MCP_DATA", Path.home() / ".local" / "share" / "strix-mcp"))
LOGS_DIR = DATA_DIR / "logs"
WORK_DIR = Path(os.environ.get("STRIX_MCP_WORK", DATA_DIR / "work"))
JOBS_FILE = DATA_DIR / "jobs.json"

for _d in (DATA_DIR, LOGS_DIR, WORK_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Command resolution
# ---------------------------------------------------------------------------


def strix_bin() -> str:
    """Absolute path to the strix executable, or raise with a useful message."""
    override = os.environ.get("STRIX_BIN")
    if override and Path(override).exists():
        return override
    found = shutil.which("strix")
    if found:
        return found
    for candidate in (Path.home() / ".local" / "bin" / "strix", Path("/usr/local/bin/strix")):
        if candidate.exists():
            return str(candidate)
    raise RuntimeError(
        "strix executable not found. Install it (uv tool install strix-agent) "
        "or set STRIX_BIN to its path."
    )


# ---------------------------------------------------------------------------
# Run-directory helpers (mirror of strix.core.paths)
# ---------------------------------------------------------------------------

RUNS_DIR_NAME = "strix_runs"


def runs_base(cwd: Path) -> Path:
    return cwd / RUNS_DIR_NAME


def run_dir(cwd: Path, run_name: str) -> Path:
    return runs_base(cwd) / run_name


def latest_run_name(cwd: Path) -> str | None:
    base = runs_base(cwd)
    if not base.is_dir():
        return None
    candidates = [c for c in base.iterdir() if (c / "run.json").is_file()]
    if not candidates:
        return None
    newest = max(candidates, key=lambda c: (c / "run.json").stat().st_mtime)
    return newest.name


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Job registry
# ---------------------------------------------------------------------------


class Job:
    __slots__ = (
        "id",
        "cmd",
        "cwd",
        "log",
        "proc",
        "status",
        "exit_code",
        "started",
        "ended",
        "targets",
        "instruction",
        "run_name",
    )

    def __init__(self, cmd: list[str], cwd: Path, targets: list[str], instruction: str | None):
        self.id = uuid.uuid4().hex[:12]
        self.cmd = cmd
        self.cwd = cwd
        self.log = LOGS_DIR / f"{self.id}.log"
        self.proc: subprocess.Popen[bytes] | None = None
        self.status = "starting"
        self.exit_code: int | None = None
        self.started = time.time()
        self.ended: float | None = None
        self.targets = targets
        self.instruction = instruction
        self.run_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "exit_code": self.exit_code,
            "started": self.started,
            "ended": self.ended,
            "cwd": str(self.cwd),
            "targets": self.targets,
            "instruction": self.instruction,
            "run_name": self.run_name,
            "log": str(self.log),
            "cmd": self.cmd,
        }


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()


def _persist_jobs() -> None:
    try:
        payload = [j.to_dict() for j in _JOBS.values()]
        tmp = JOBS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(JOBS_FILE)
    except OSError:
        pass


def _load_jobs() -> None:
    """Re-attach to jobs started by a previous server process where possible."""
    data = read_json(JOBS_FILE)
    if not isinstance(data, list):
        return
    for row in data:
        if not isinstance(row, dict) or "id" not in row:
            continue
        job = Job(
            row.get("cmd", []),
            Path(row.get("cwd", WORK_DIR)),
            row.get("targets", []),
            row.get("instruction"),
        )
        job.id = row["id"]
        job.log = Path(row.get("log", LOGS_DIR / f"{job.id}.log"))
        job.status = row.get("status", "unknown")
        job.exit_code = row.get("exit_code")
        job.started = row.get("started", time.time())
        job.ended = row.get("ended")
        job.run_name = row.get("run_name")
        if job.status in ("starting", "running"):
            job.status = "unknown (process gone)"
        _JOBS[job.id] = job


def _supervise(job: Job) -> None:
    assert job.proc is not None
    code = job.proc.wait()
    with _JOBS_LOCK:
        job.exit_code = code
        job.ended = time.time()
        if job.status == "stopping":
            job.status = "stopped"
        else:
            job.status = "completed" if code == 0 else "failed"
        if job.run_name is None:
            job.run_name = latest_run_name(job.cwd)
        _persist_jobs()


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------


def build_command(
    targets: list[str] | None,
    *,
    non_interactive: bool,
    instruction: str | None,
    instruction_file: str | None,
    target_list: list[str] | None,
    workspace_file: list[str] | None,
    scan_mode: str | None,
    scope_mode: str | None,
    diff_base: str | None,
    config: str | None,
    mcp_config: str | None,
    mcp_server: list[str] | None,
    mcp_exclude: list[str] | None,
    max_budget: float | None,
    max_turns: int | None,
    fail_on: str | None,
    resume: str | None,
    extra_args: list[str] | None,
) -> list[str]:
    cmd: list[str] = [strix_bin()]
    if non_interactive:
        cmd.append("--non-interactive")
    for t in targets or []:
        cmd += ["--target", t]
    for t in target_list or []:
        cmd += ["--target-list", t]
    if instruction:
        cmd += ["--instruction", instruction]
    if instruction_file:
        cmd += ["--instruction-file", instruction_file]
    for wf in workspace_file or []:
        cmd += ["--workspace-file", wf]
    if scan_mode:
        cmd += ["--scan-mode", scan_mode]
    if scope_mode:
        cmd += ["--scope-mode", scope_mode]
    if diff_base:
        cmd += ["--diff-base", diff_base]
    if config:
        cmd += ["--config", config]
    if mcp_config:
        cmd += ["--mcp-config", mcp_config]
    for s in mcp_server or []:
        cmd += ["--mcp-server", s]
    for s in mcp_exclude or []:
        cmd += ["--mcp-exclude", s]
    if max_budget is not None:
        cmd += ["--max-budget", str(max_budget)]
    if max_turns is not None:
        cmd += ["--max-turns", str(max_turns)]
    if fail_on:
        cmd += ["--fail-on", fail_on]
    if resume:
        cmd += ["--resume", resume]
    if extra_args:
        cmd += list(extra_args)
    return cmd


def launch(
    targets: list[str] | None = None,
    *,
    cwd: str | None = None,
    instruction: str | None = None,
    instruction_file: str | None = None,
    target_list: list[str] | None = None,
    workspace_file: list[str] | None = None,
    scan_mode: str | None = None,
    scope_mode: str | None = None,
    diff_base: str | None = None,
    config: str | None = None,
    mcp_config: str | None = None,
    mcp_server: list[str] | None = None,
    mcp_exclude: list[str] | None = None,
    max_budget: float | None = None,
    max_turns: int | None = None,
    fail_on: str | None = None,
    resume: str | None = None,
    extra_args: list[str] | None = None,
    env: dict[str, str] | None = None,
    non_interactive: bool = True,
) -> Job:
    if not targets and not target_list and not resume:
        raise ValueError("provide at least one target (or target_list, or resume)")

    workdir = Path(cwd).expanduser().resolve() if cwd else WORK_DIR
    workdir.mkdir(parents=True, exist_ok=True)

    cmd = build_command(
        targets,
        non_interactive=non_interactive,
        instruction=instruction,
        instruction_file=instruction_file,
        target_list=target_list,
        workspace_file=workspace_file,
        scan_mode=scan_mode,
        scope_mode=scope_mode,
        diff_base=diff_base,
        config=config,
        mcp_config=mcp_config,
        mcp_server=mcp_server,
        mcp_exclude=mcp_exclude,
        max_budget=max_budget,
        max_turns=max_turns,
        fail_on=fail_on,
        resume=resume,
        extra_args=extra_args,
    )

    child_env = os.environ.copy()
    if env:
        child_env.update({str(k): str(v) for k, v in env.items()})
    child_env.setdefault("PYTHONUNBUFFERED", "1")

    job = Job(cmd, workdir, list(targets or []), instruction)
    log_fh = job.log.open("wb")
    log_fh.write(f"# cmd: {' '.join(cmd)}\n".encode())
    log_fh.write(f"# cwd: {workdir}\n".encode())
    log_fh.flush()

    proc = subprocess.Popen(
        cmd,
        cwd=str(workdir),
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=child_env,
        start_new_session=True,
    )
    job.proc = proc
    job.status = "running"

    with _JOBS_LOCK:
        _JOBS[job.id] = job
        _persist_jobs()

    threading.Thread(target=_supervise, args=(job,), daemon=True).start()
    return job


# ---------------------------------------------------------------------------
# Log reading
# ---------------------------------------------------------------------------


def tail(path: Path, lines: int) -> str:
    if not path.exists():
        return ""
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= lines:
                step = min(block, size)
                size -= step
                fh.seek(size)
                data = fh.read(step) + data
                block *= 2
            return data.decode("utf-8", "replace")
    except OSError as exc:
        return f"<log read error: {exc}>"


def refresh(job: Job) -> None:
    if job.proc is not None and job.status in ("starting", "running"):
        code = job.proc.poll()
        if code is not None:
            with _JOBS_LOCK:
                job.exit_code = code
                job.ended = job.ended or time.time()
                job.status = "completed" if code == 0 else "failed"
                if job.run_name is None:
                    job.run_name = latest_run_name(job.cwd)
                _persist_jobs()


def get_job(job_id: str) -> Job:
    job = _JOBS.get(job_id)
    if job is None:
        raise ValueError(f"unknown job id {job_id!r}")
    return job


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

_INSTRUCTIONS = (
    "Strix is an autonomous multi-agent penetration-testing tool. Use "
    "strix_start_scan for long scans (returns immediately with a job id) and "
    "strix_job_status / strix_job_log to watch progress. Use strix_scan when "
    "you want to wait for a bounded result. Reports land under "
    "<cwd>/strix_runs/<run_name>/penetration_test_report.md; read them with "
    "strix_run_report."
)
if _MCP_API == 2:
    server = _Server(name=SERVER_NAME, version=SERVER_VERSION, instructions=_INSTRUCTIONS)
else:
    server = _Server(name=SERVER_NAME, instructions=_INSTRUCTIONS)

try:
    server.description = "Run and monitor Strix penetration tests over MCP."
except Exception:
    pass


@server.tool()
def strix_version() -> str:
    """Return the installed Strix version (and its resolved path)."""
    out = subprocess.run([strix_bin(), "--version"], capture_output=True, text=True, timeout=30)
    return f"{out.stdout.strip() or out.stderr.strip()}  [{strix_bin()}]"


@server.tool()
def strix_start_scan(
    targets: list[str],
    instruction: str | None = None,
    scan_mode: str | None = None,
    cwd: str | None = None,
    target_list: list[str] | None = None,
    workspace_file: list[str] | None = None,
    scope_mode: str | None = None,
    diff_base: str | None = None,
    mcp_config: str | None = None,
    mcp_server: list[str] | None = None,
    mcp_exclude: list[str] | None = None,
    max_budget: float | None = None,
    max_turns: int | None = None,
    fail_on: str | None = None,
    resume: str | None = None,
    extra_args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Launch a Strix scan in the background and return a job id immediately.

    targets: URLs, domains, IPs, repo URLs, local dirs, or API spec files.
    instruction: focus/credentials, e.g. "Focus on IDOR and auth".
    scan_mode: quick | standard | deep.
    cwd: working directory (scan artifacts go to <cwd>/strix_runs). Defaults to
         the strix-mcp work dir.
    resume: run name under strix_runs to resume.
    Watch it with strix_job_status and strix_job_log.
    """
    try:
        job = launch(
            targets,
            cwd=cwd,
            instruction=instruction,
            target_list=target_list,
            workspace_file=workspace_file,
            scan_mode=scan_mode,
            scope_mode=scope_mode,
            diff_base=diff_base,
            mcp_config=mcp_config,
            mcp_server=mcp_server,
            mcp_exclude=mcp_exclude,
            max_budget=max_budget,
            max_turns=max_turns,
            fail_on=fail_on,
            resume=resume,
            extra_args=extra_args,
            env=env,
        )
    except Exception as exc:
        return f"error: {exc}"
    return json.dumps(
        {"job_id": job.id, "status": job.status, "cwd": str(job.cwd), "log": str(job.log)},
        indent=2,
    )


@server.tool()
def strix_scan(
    targets: list[str],
    instruction: str | None = None,
    scan_mode: str | None = None,
    cwd: str | None = None,
    wait_seconds: int = 120,
    tail_lines: int = 60,
    resume: str | None = None,
    max_budget: float | None = None,
    max_turns: int | None = None,
    fail_on: str | None = None,
    extra_args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Start a scan and wait up to wait_seconds for it to finish.

    Returns the final status and the tail of the log when it finishes inside the
    window; otherwise returns the live job id so you can keep polling.
    """
    try:
        job = launch(
            targets,
            cwd=cwd,
            instruction=instruction,
            scan_mode=scan_mode,
            resume=resume,
            max_budget=max_budget,
            max_turns=max_turns,
            fail_on=fail_on,
            extra_args=extra_args,
            env=env,
        )
    except Exception as exc:
        return f"error: {exc}"

    deadline = time.time() + max(0, wait_seconds)
    while time.time() < deadline and job.status in ("starting", "running"):
        time.sleep(1)
        refresh(job)
    refresh(job)

    result = {
        "job_id": job.id,
        "status": job.status,
        "exit_code": job.exit_code,
        "run_name": job.run_name,
        "cwd": str(job.cwd),
    }
    if job.status in ("starting", "running"):
        result["note"] = "still running; poll with strix_job_status"
    else:
        with _JOBS_LOCK:
            job.run_name = job.run_name or latest_run_name(job.cwd)
        result["run_name"] = job.run_name
    result["log_tail"] = tail(job.log, tail_lines)
    return json.dumps(result, indent=2)


@server.tool()
def strix_job_status(job_id: str, tail_lines: int = 40) -> str:
    """Status of a scan job: state, exit code, run name, and a log tail."""
    try:
        job = get_job(job_id)
    except Exception as exc:
        return f"error: {exc}"
    refresh(job)
    if job.status not in ("starting", "running") and job.run_name is None:
        with _JOBS_LOCK:
            job.run_name = latest_run_name(job.cwd)
            _persist_jobs()
    payload = job.to_dict()
    payload["log_tail"] = tail(job.log, tail_lines)
    return json.dumps(payload, indent=2)


@server.tool()
def strix_job_log(job_id: str, tail_lines: int = 200) -> str:
    """Return the last tail_lines of a job's combined stdout/stderr."""
    try:
        job = get_job(job_id)
    except Exception as exc:
        return f"error: {exc}"
    return tail(job.log, tail_lines) or "<empty log>"


@server.tool()
def strix_job_stop(job_id: str) -> str:
    """Stop a running scan job (SIGTERM then SIGKILL)."""
    try:
        job = get_job(job_id)
    except Exception as exc:
        return f"error: {exc}"
    proc = job.proc
    if proc is None or proc.poll() is not None:
        refresh(job)
        return json.dumps({"job_id": job.id, "status": job.status}, indent=2)
    with _JOBS_LOCK:
        job.status = "stopping"
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except OSError:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            proc.kill()
    with _JOBS_LOCK:
        if job.status != "stopped":
            job.status = "stopped"
        job.exit_code = proc.returncode
        _persist_jobs()
    return json.dumps(
        {"job_id": job.id, "status": job.status, "exit_code": job.exit_code}, indent=2
    )


@server.tool()
def strix_jobs() -> str:
    """List every scan job this server knows about, newest first."""
    rows = []
    for job in _JOBS.values():
        refresh(job)
        rows.append(job.to_dict())
    rows.sort(key=lambda r: r["started"], reverse=True)
    return json.dumps(rows, indent=2)


@server.tool()
def strix_list_runs(cwd: str | None = None) -> str:
    """List Strix runs found under <cwd>/strix_runs (status, findings, target)."""
    base = Path(cwd).expanduser().resolve() if cwd else WORK_DIR
    runs_root = runs_base(base)
    if not runs_root.is_dir():
        return json.dumps({"cwd": str(base), "runs": []}, indent=2)

    def _mtime(c: Path) -> float:
        record = c / "run.json"
        return record.stat().st_mtime if record.is_file() else 0.0

    rows: list[dict[str, Any]] = []
    for child in sorted(runs_root.iterdir(), key=_mtime, reverse=True):
        record = read_json(child / "run.json")
        if not isinstance(record, dict):
            continue
        findings = read_json(child / "vulnerabilities.json")
        rows.append(
            {
                "run_name": child.name,
                "status": record.get("status"),
                "start_time": record.get("start_time"),
                "end_time": record.get("end_time"),
                "findings": len(findings) if isinstance(findings, list) else None,
                "path": str(child),
            }
        )
    return json.dumps({"cwd": str(base), "runs": rows}, indent=2)


def _resolve_run(cwd: Path, run_name: str | None) -> Path:
    name = run_name or latest_run_name(cwd)
    if not name:
        raise ValueError(f"no runs found under {runs_base(cwd)}")
    d = run_dir(cwd, name)
    if not d.is_dir():
        raise ValueError(f"run {name!r} not found under {runs_base(cwd)}")
    return d


@server.tool()
def strix_run_report(run_name: str | None = None, cwd: str | None = None) -> str:
    """Read a run's Markdown report. Defaults to the most recent run."""
    base = Path(cwd).expanduser().resolve() if cwd else WORK_DIR
    try:
        d = _resolve_run(base, run_name)
    except Exception as exc:
        return f"error: {exc}"
    report = d / "penetration_test_report.md"
    if not report.is_file():
        available = [p.name for p in d.iterdir()] if d.is_dir() else []
        return f"error: no report at {report}. Files present: {available}"
    return report.read_text(encoding="utf-8", errors="replace")


@server.tool()
def strix_run_findings(run_name: str | None = None, cwd: str | None = None) -> str:
    """Read a run's vulnerabilities.json (structured findings). Defaults to latest."""
    base = Path(cwd).expanduser().resolve() if cwd else WORK_DIR
    try:
        d = _resolve_run(base, run_name)
    except Exception as exc:
        return f"error: {exc}"
    data = read_json(d / "vulnerabilities.json")
    if data is None:
        return f"error: no vulnerabilities.json under {d}"
    return json.dumps(data, indent=2)


@server.resource("strix://jobs")
def jobs_resource() -> str:
    """JSON index of scan jobs known to this server."""
    return strix_jobs()


@server.resource("strix://runs")
def runs_resource() -> str:
    """JSON index of Strix runs in the default work directory."""
    return strix_list_runs()


@server.prompt()
def pentest(target: str, focus: str = "general security review") -> str:
    """Plan and run a Strix pentest against a target."""
    return (
        f"Run a Strix penetration test against {target}. Focus: {focus}.\n"
        "Use strix_start_scan, then poll strix_job_status until the job finishes, "
        "and finally summarise strix_run_report for the run."
    )


def _selftest() -> int:
    print(f"mcp api v{_MCP_API}, server={SERVER_NAME} {SERVER_VERSION}")
    print("strix:", strix_bin())
    print("data:", DATA_DIR)
    print("work:", WORK_DIR)
    job = launch(
        ["example.com"], instruction="selftest (dry)", scan_mode="quick", extra_args=["--help"]
    )
    time.sleep(2)
    refresh(job)
    print("launch ok, job:", job.id, "status:", job.status)
    return 0


def main() -> None:
    _load_jobs()
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
