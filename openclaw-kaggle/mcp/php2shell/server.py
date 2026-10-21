#!/usr/bin/env python3
"""PHP2Shell MCP server: passive CVE assessment plus loopback-only verification.

Passive tools are safe against arbitrary HTTP targets: version parsing, header
fingerprinting, advisory data, pinned-repository status, and lab inventory.
The active verifier wraps the upstream POC scripts and refuses every target
that does not resolve exclusively to loopback.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urljoin, urlsplit

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server


PINNED_REVISION = "6d2168710509a2647545ba78d68afb1e3f745038"
PINNED_REPOSITORY = "https://github.com/ikow/php2shell-poc.git"
PINNED_VERSION = "1.0.0"
AFFECTED_RANGE = "5.4.0 through 8.5.11"
FIXED_VERSIONS = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
MIN_AFFECTED = (5, 4, 0)
CVES = [
    {
        "id": "CVE-2026-109618",
        "ghsa": "GHSA-w8hw-w9fx-j79w",
        "title": "RCE via OOM corruption: longjmp() leaves request state invalid",
        "cvss": "9.2",
        "severity": "critical",
        "authentication": "none",
    },
    {
        "id": "CVE-2026-109619",
        "ghsa": "GHSA-6wmf-4rv5-p3rp",
        "title": "RCE via stale global state: worker retains freed request memory",
        "cvss": "9.2",
        "severity": "critical",
        "authentication": "none",
    },
]
CHAINS = {
    "session_injection": {
        "cve": "CVE-2026-109618/109619",
        "name": "Chain A - session file injection via upload_progress filename",
        "requires": "session.upload_progress enabled; an include/LFI sink for code execution",
        "script": "verify_session_injection.py",
    },
    "uaf_asan": {
        "cve": "CVE-2026-109619",
        "name": "Chain B - var_destroy UAF under ASAN",
        "requires": "ASAN-instrumented PHP CLI; controlled unserialize() input",
        "script": "verify_uaf_asan.php",
    },
    "handler_mismatch": {
        "cve": "CVE-2026-109618/109619",
        "name": "Chain C - session handler mismatch drives __destruct",
        "requires": "two session prefixes with different serialize_handler sharing save_path",
        "script": "verify_handler_mismatch.py",
    },
    "oom": {
        "cve": "CVE-2026-109618",
        "name": "Chain D - mod_php request-startup OOM to stale EG()",
        "requires": "Apache mod_php or FrankenPHP; no application primitive",
        "script": "verify_oom_trigger.py",
    },
    "fpm_stale": {
        "cve": "CVE-2026-109619",
        "name": "Chain E - FPM session decode OOM leaves stale BG(unserialize)",
        "requires": "PHP-FPM, memory_limit <= 32M, pm.max_children=1, ~30MB session file",
        "script": "verify_fpm_stale_state.py",
    },
}
SAPI_CHAINS = {
    "apache2handler": ["session_injection", "uaf_asan", "handler_mismatch", "oom"],
    "mod_php": ["session_injection", "uaf_asan", "handler_mismatch", "oom"],
    "fpm-fcgi": ["session_injection", "uaf_asan", "handler_mismatch", "fpm_stale"],
    "frankenphp": ["session_injection", "uaf_asan", "handler_mismatch", "oom"],
    "cli-server": ["session_injection", "uaf_asan", "handler_mismatch"],
    "cli": ["session_injection", "uaf_asan", "handler_mismatch"],
}
MITIGATIONS = [
    {"control": "session.upload_progress.enabled = Off", "blocks": "Chains A, C, E (partial)"},
    {"control": "session.use_only_cookies = On", "blocks": "Chains A, C (fixation vector)"},
    {"control": "memory_limit/post_max_size tuning", "blocks": "reduces Chain D/E OOM surface"},
    {"control": "PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12", "blocks": "all chains (complete fix)"},
]

REPO_DIR = Path(os.environ.get("PHP2SHELL_REPO", Path.home() / "php2shell-poc")).expanduser()
STATE_DIR = Path(os.environ.get("PHP2SHELL_STATE_DIR", Path.home() / ".local/share/php2shell-mcp")).expanduser()
RUNS_DIR = STATE_DIR / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)

VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$")
SID_RE = re.compile(r"^[A-Za-z0-9]{1,128}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fec0::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
]
app = Server("php2shell-server")


def text(value: str) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=value)]


def dump(value: dict) -> list[types.TextContent]:
    return text(json.dumps(value, indent=2))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_version(value: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.search(value or "")
    if not match:
        return None
    major, minor, patch = match.group(1), match.group(2), match.group(3)
    return int(major), int(minor), int(patch or 0)


def version_string(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def assess_version(version: tuple[int, int, int]) -> dict:
    major, minor, _ = version
    fixed = FIXED_VERSIONS.get((major, minor))
    if version < MIN_AFFECTED:
        status = "not_affected"
        detail = f"Released before session.upload_progress existed ({AFFECTED_RANGE})."
    elif fixed is None:
        status = "vulnerable_eol"
        detail = "Branch predates the maintained fix releases; no patched build exists for it."
    elif version < fixed:
        status = "vulnerable"
        detail = f"Upgrade to {version_string(fixed)} or later."
    else:
        status = "patched"
        detail = f"At or above the fixed release for the {major}.{minor} branch."
    return {
        "version": version_string(version),
        "status": status,
        "fixed_version": version_string(fixed) if fixed else None,
        "detail": detail,
        "affected_range": AFFECTED_RANGE,
        "cves": [cve["id"] for cve in CVES],
    }


def normalize_path(value: str, label: str) -> str:
    if not PATH_RE.fullmatch(value):
        raise ValueError(f"{label} must be an absolute URL path without whitespace or control characters")
    return value


def normalize_sid(value: str, label: str) -> str:
    if not SID_RE.fullmatch(value):
        raise ValueError(f"{label} must be 1-128 alphanumeric characters")
    return value


def resolve_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve host {host!r}: {exc}") from exc
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        raw = info[4][0].split("%", 1)[0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError(f"host {host!r} produced no usable addresses")
    return addresses


def validate_passive_url(raw: str) -> tuple[str, str, int]:
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ValueError("only http and https targets are accepted")
    if parts.username or parts.password:
        raise ValueError("credentials in the URL are not accepted")
    host = parts.hostname
    if not host:
        raise ValueError("target URL is missing a host")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("target URL has an invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("target port must be between 1 and 65535")
    for address in resolve_host(host):
        for network in BLOCKED_NETWORKS:
            if address.version == network.version and address in network:
                raise ValueError(f"target resolves to blocked address {address}; metadata and link-local ranges are refused")
    netloc = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{netloc}:{port}", host, port


def validate_loopback_target(raw: str) -> tuple[str, str, int]:
    normalized, host, port = validate_passive_url(raw)
    addresses = resolve_host(host)
    if not addresses or any(not address.is_loopback for address in addresses):
        raise ValueError(f"active verification is loopback-only; {host!r} resolved to {[str(a) for a in addresses]}")
    return normalized, host, port


def require_loopback_host(host: str) -> str:
    if not HOST_RE.fullmatch(host):
        raise ValueError("host is not a valid hostname or IP address")
    addresses = resolve_host(host)
    if not addresses or any(not address.is_loopback for address in addresses):
        raise ValueError(f"active verification is loopback-only; {host!r} resolved to {[str(a) for a in addresses]}")
    return host


def fetch_headers(url: str, timeout: float, max_redirects: int = 3, verify_tls: bool = True) -> dict:
    current = url
    hops: list[dict] = []
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    for _ in range(max_redirects + 1):
        normalized, host, port = validate_passive_url(current)
        parts = urlsplit(normalized)
        connection_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        kwargs = {"timeout": timeout}
        if parts.scheme == "https":
            kwargs["context"] = context
        connection = connection_cls(host, port, **kwargs)
        try:
            connection.request(
                "HEAD",
                parts.path or "/",
                headers={"User-Agent": "php2shell-mcp/passive", "Accept": "*/*", "Connection": "close"},
            )
            response = connection.getresponse()
            headers: dict[str, list[str]] = {}
            for key, value in response.getheaders():
                headers.setdefault(key.lower(), []).append(value)
            status = response.status
            location = response.getheader("Location")
            if status in (301, 302, 303, 307, 308) and location:
                hops.append({"url": normalized, "status": status, "location": location})
                current = urljoin(normalized, location)
                continue
            return {"url": normalized, "status": status, "headers": headers, "redirects": hops}
        finally:
            connection.close()
    raise ValueError(f"more than {max_redirects} redirects")


def header_value(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name.lower(), [])
    return values[0] if values else ""


def detect_from_headers(headers: dict[str, list[str]]) -> dict:
    powered = header_value(headers, "x-powered-by")
    server = header_value(headers, "server")
    candidates = [powered, server]
    cookies = " ".join(headers.get("set-cookie", []))
    version = None
    source = None
    for label, candidate in (("x-powered-by", powered), ("server", server)):
        parsed = parse_version(candidate)
        if parsed:
            version = parsed
            source = label
            break
    sapi_hint = "unknown"
    haystack = f"{server} {powered}".lower()
    if "apache" in haystack and "php" in haystack:
        sapi_hint = "apache2handler"
    elif "nginx" in haystack or "fpm" in haystack:
        sapi_hint = "fpm-fcgi"
    elif "frankenphp" in haystack:
        sapi_hint = "frankenphp"
    return {
        "php_version": version_string(version) if version else None,
        "version_source": source,
        "server": server,
        "x_powered_by": powered,
        "sapi_hint": sapi_hint,
        "phpsessid_cookie": "phpsessid" in cookies.lower(),
        "raw_candidates": [item for item in candidates if item],
    }


def repo_head() -> tuple[str | None, str | None]:
    if not (REPO_DIR / ".git").exists():
        return None, f"no git checkout at {REPO_DIR}"
    try:
        head = subprocess.run(
            ["git", "-C", str(REPO_DIR), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if head.returncode != 0:
            return None, head.stderr.strip() or "git rev-parse failed"
        return head.stdout.strip(), None
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)


def script_digests() -> dict:
    poc = REPO_DIR / "poc"
    if not poc.is_dir():
        return {}
    digests = {}
    for path in sorted(poc.iterdir()):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            digests[path.name] = {"sha256": digest, "bytes": path.stat().st_size}
    return digests


def run_command(argv: list[str], timeout: int, env: dict | None = None, cwd: Path | None = None) -> dict:
    started = time.time()
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=child_env,
            cwd=str(cwd) if cwd else None,
        )
        return {
            "argv": argv,
            "returncode": result.returncode,
            "duration_seconds": round(time.time() - started, 2),
            "stdout": result.stdout[-20000:],
            "stderr": result.stderr[-20000:],
        }
    except FileNotFoundError as exc:
        return {"argv": argv, "returncode": 127, "duration_seconds": round(time.time() - started, 2),
                "stdout": "", "stderr": f"command unavailable: {exc.filename}"}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {"argv": argv, "returncode": 124, "duration_seconds": round(time.time() - started, 2),
                "stdout": stdout[-20000:], "stderr": (stderr or f"timed out after {timeout}s")[-20000:]}


def interpret(chain: str, result: dict) -> list[str]:
    output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    indicators: list[str] = []
    if result["returncode"] == 124:
        indicators.append("verifier exceeded its timeout")
    if "VULNERABLE" in output:
        indicators.append("verifier reported VULNERABLE")
    if "destruction failed" in output.lower():
        indicators.append("stale session destruction observed (Chain C/E indicator)")
    if "Failed to decode session object" in output:
        indicators.append("session handler mismatch decoded attacker data")
    if chain == "oom":
        if "500" in output:
            indicators.append("HTTP 500 after OOM payload")
        if "crashed" in output.lower() or "No response" in output:
            indicators.append("connection dropped; worker may have crashed")
    if result["returncode"] == 0 and not indicators:
        indicators.append("verifier finished cleanly; inspect stdout for target-specific evidence")
    if result["returncode"] not in (0, 124) and not indicators:
        indicators.append(f"verifier exited with code {result['returncode']}")
    return indicators


def persist_run(record: dict) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = RUNS_DIR / f"{stamp}-{record['chain']}-{record['report_id']}.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return path


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    empty = {"type": "object", "properties": {}, "required": []}
    return [
        types.Tool(
            name="php2shell_advisory",
            description="Return the CVE-2026-109618/109619 advisory matrix, fixed releases, SAPI exposure, and mitigations",
            inputSchema=empty,
        ),
        types.Tool(
            name="php2shell_check_version",
            description="Assess a PHP version string against the PHP2Shell fixed releases (passive)",
            inputSchema={
                "type": "object",
                "properties": {
                    "version": {"type": "string", "description": "PHP version, e.g. 8.2.34 or PHP/8.3.10"},
                    "sapi": {"type": "string", "description": "Optional SAPI: apache2handler, fpm-fcgi, frankenphp, cli-server"},
                },
                "required": ["version"],
            },
        ),
        types.Tool(
            name="php2shell_fingerprint",
            description="Passively fingerprint a live HTTP endpoint (headers only) and assess the exposed PHP version",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "http(s) URL to inspect"},
                    "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 30, "default": 10},
                    "verify_tls": {"type": "boolean", "default": True},
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="php2shell_repo_status",
            description="Verify the pinned php2shell-poc checkout, HEAD revision, and POC script digests",
            inputSchema=empty,
        ),
        types.Tool(
            name="php2shell_lab_status",
            description="Inventory the local lab: docker/compose, PHP CLI and ASAN linkage, loopback listeners",
            inputSchema=empty,
        ),
        types.Tool(
            name="php2shell_verify",
            description="Run an upstream PHP2Shell verification chain against a loopback target only",
            inputSchema={
                "type": "object",
                "properties": {
                    "chain": {"type": "string", "enum": sorted(CHAINS)},
                    "target": {"type": "string", "default": "http://127.0.0.1:18080"},
                    "path": {"type": "string", "default": "/index.php"},
                    "write_path": {"type": "string", "default": "/app/upload.php"},
                    "read_path": {"type": "string", "default": "/api/endpoint.php"},
                    "sid": {"type": "string", "default": "verify0000000000000000"},
                    "strategy": {"type": "string", "enum": ["headers", "nested", "no_length"], "default": "headers"},
                    "num_headers": {"type": "integer", "minimum": 1, "maximum": 20000, "default": 5000},
                    "header_size": {"type": "integer", "minimum": 1, "maximum": 2048, "default": 500},
                    "depth": {"type": "integer", "minimum": 1, "maximum": 16, "default": 10},
                    "width": {"type": "integer", "minimum": 1, "maximum": 4000, "default": 1000},
                    "total_mb": {"type": "integer", "minimum": 1, "maximum": 256, "default": 128},
                    "session_path": {"type": "string", "default": "/session_oom.php"},
                    "upload_path": {"type": "string", "default": "/index.php"},
                    "producer_sid": {"type": "string", "default": "hugesession000000000000000"},
                    "consumer_sid": {"type": "string", "default": "consumerpoisoned0000000000"},
                    "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 180, "default": 120},
                },
                "required": ["chain"],
            },
        ),
        types.Tool(
            name="php2shell_runs",
            description="List persisted PHP2Shell verification reports, newest first",
            inputSchema={
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
                "required": [],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        if name == "php2shell_advisory":
            return dump({
                "advisories": CVES,
                "affected_range": AFFECTED_RANGE,
                "fixed_releases": {f"{k[0]}.{k[1]}": version_string(v) for k, v in FIXED_VERSIONS.items()},
                "sapi_exposure": {sapi: [CHAINS[chain]["name"] for chain in chains] for sapi, chains in SAPI_CHAINS.items()},
                "chains": CHAINS,
                "mitigations": MITIGATIONS,
                "patch_commit": "https://github.com/php/php-src/commit/3584a98bda",
                "pinned_repository": {"url": PINNED_REPOSITORY, "revision": PINNED_REVISION},
                "note": "Active verification is restricted to loopback targets; passive header and version checks are unrestricted.",
            })

        if name == "php2shell_check_version":
            parsed = parse_version(arguments["version"])
            if not parsed:
                raise ValueError("version must contain a numeric PHP version such as 8.2.34")
            assessment = assess_version(parsed)
            sapi = (arguments.get("sapi") or "").strip().lower()
            if sapi:
                if sapi not in SAPI_CHAINS:
                    raise ValueError(f"unknown SAPI {sapi!r}; expected one of {sorted(SAPI_CHAINS)}")
                assessment["sapi"] = sapi
                assessment["exposed_chains"] = [CHAINS[chain]["name"] for chain in SAPI_CHAINS[sapi]]
            return dump(assessment)

        if name == "php2shell_fingerprint":
            url = arguments["target"]
            timeout = float(arguments.get("timeout_seconds", 10))
            response = fetch_headers(url, timeout, verify_tls=bool(arguments.get("verify_tls", True)))
            detected = detect_from_headers(response["headers"])
            payload = {
                "url": response["url"],
                "status": response["status"],
                "redirects": response["redirects"],
                "detected": detected,
                "headers": {key: values for key, values in sorted(response["headers"].items())},
                "passive": True,
            }
            if detected["php_version"]:
                payload["assessment"] = assess_version(parse_version(detected["php_version"]))
            else:
                payload["assessment"] = {
                    "status": "unknown",
                    "detail": "No PHP version is exposed in Server or X-Powered-By headers.",
                }
            return dump(payload)

        if name == "php2shell_repo_status":
            head, error = repo_head()
            payload = {
                "repository": PINNED_REPOSITORY,
                "path": str(REPO_DIR),
                "expected_revision": PINNED_REVISION,
                "head_revision": head,
                "revision_matches": head == PINNED_REVISION,
                "error": error,
                "scripts": script_digests(),
            }
            if head:
                payload["dirty"] = bool(run_command(["git", "-C", str(REPO_DIR), "status", "--porcelain"], 20)["stdout"].strip())
            return dump(payload)

        if name == "php2shell_lab_status":
            php = shutil.which("php") or os.environ.get("PHP2SHELL_PHP", "")
            php_version = run_command([php, "-v"], 20) if php else {"returncode": 127, "stdout": "", "stderr": "php not found"}
            asan = {"linked": False}
            if php:
                ldd = run_command(["ldd", php], 20)
                asan = {"linked": "libasan" in ldd["stdout"], "detail": ldd["stdout"][:2000]}
            docker = shutil.which("docker")
            docker_info = run_command(["docker", "info", "--format", "{{.ServerVersion}}"], 10) if docker else {"returncode": 127, "stdout": "", "stderr": "docker not found"}
            compose = run_command(["docker", "compose", "version", "--short"], 15) if docker else {"returncode": 127, "stdout": "", "stderr": "docker not found"}
            containers = run_command(["docker", "ps", "--filter", "name=php2shell", "--format", "{{.Names}}\t{{.Status}}"], 15) if docker else {"returncode": 127, "stdout": "", "stderr": "docker not found"}
            listeners = {}
            for port in (18080, 18081):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.5)
                    listeners[str(port)] = probe.connect_ex(("127.0.0.1", port)) == 0
            head, error = repo_head()
            return dump({
                "repository": {"path": str(REPO_DIR), "head_revision": head, "revision_matches": head == PINNED_REVISION, "error": error},
                "php": {"binary": php or None, "first_line": (php_version.get("stdout") or "").splitlines()[0] if php_version.get("stdout") else None},
                "asan": asan,
                "docker": {"binary": docker, "server_version": docker_info.get("stdout", "").strip() or None, "error": docker_info.get("stderr", "").strip() or None},
                "compose_version": compose.get("stdout", "").strip() or None,
                "containers": [line for line in containers.get("stdout", "").splitlines() if line],
                "loopback_listeners": listeners,
            })

        if name == "php2shell_verify":
            chain = arguments["chain"]
            if chain not in CHAINS:
                raise ValueError(f"unknown chain {chain!r}")
            timeout = int(arguments.get("timeout_seconds", 120))
            script = REPO_DIR / "poc" / CHAINS[chain]["script"]
            if not script.is_file():
                raise ValueError(f"verification script missing at {script}; run install_security_tools.sh")

            if chain == "uaf_asan":
                php = os.environ.get("PHP2SHELL_PHP") or shutil.which("php")
                if not php:
                    raise ValueError("php CLI is unavailable and PHP2SHELL_PHP is not set")
                result = run_command(
                    [php, str(script)],
                    timeout,
                    env={"USE_ZEND_ALLOC": "0", "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"},
                    cwd=REPO_DIR,
                )
                target = None
            else:
                target, host, port = validate_loopback_target(arguments.get("target", "http://127.0.0.1:18080"))
                argv = [sys.executable, str(script)]
                if chain == "session_injection":
                    argv += ["--target", target, "--path", normalize_path(arguments.get("path", "/index.php"), "path"),
                             "--sid", normalize_sid(arguments.get("sid", "verify0000000000000000"), "sid")]
                elif chain == "handler_mismatch":
                    argv += ["--target", target,
                             "--write-path", normalize_path(arguments.get("write_path", "/app/upload.php"), "write_path"),
                             "--read-path", normalize_path(arguments.get("read_path", "/api/endpoint.php"), "read_path"),
                             "--sid", normalize_sid(arguments.get("sid", "mismatchverify0000000000000"), "sid")]
                elif chain == "oom":
                    strategy = arguments.get("strategy", "headers")
                    if strategy not in ("headers", "nested", "no_length"):
                        raise ValueError("strategy must be headers, nested, or no_length")
                    argv += ["--host", host, "--port", str(port), "--path", normalize_path(arguments.get("path", "/index.php"), "path"),
                             "--strategy", strategy,
                             "--num-headers", str(int(arguments.get("num_headers", 5000))),
                             "--header-size", str(int(arguments.get("header_size", 500))),
                             "--depth", str(int(arguments.get("depth", 10))),
                             "--width", str(int(arguments.get("width", 1000))),
                             "--total-mb", str(int(arguments.get("total_mb", 128)))]
                else:  # fpm_stale
                    argv += ["--target", target,
                             "--session-path", normalize_path(arguments.get("session_path", "/session_oom.php"), "session_path"),
                             "--upload-path", normalize_path(arguments.get("upload_path", "/index.php"), "upload_path"),
                             "--producer-sid", normalize_sid(arguments.get("producer_sid", "hugesession000000000000000"), "producer_sid"),
                             "--consumer-sid", normalize_sid(arguments.get("consumer_sid", "consumerpoisoned0000000000"), "consumer_sid")]
                result = run_command(argv, timeout, cwd=REPO_DIR)

            report_id = hashlib.sha256(f"{chain}{time.time()}".encode()).hexdigest()[:10]
            record = {
                "chain": chain,
                "chain_name": CHAINS[chain]["name"],
                "cve": CHAINS[chain]["cve"],
                "target": target,
                "started_at": now_iso(),
                "report_id": report_id,
                **result,
            }
            record["indicators"] = interpret(chain, result)
            record["report"] = str(persist_run(record))
            return dump(record)

        if name == "php2shell_runs":
            limit = int(arguments.get("limit", 20))
            if not 1 <= limit <= 100:
                raise ValueError("limit must be between 1 and 100")
            rows = []
            files = sorted(RUNS_DIR.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:limit]
            for path in files:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                rows.append({
                    "report": str(path),
                    "chain": data.get("chain"),
                    "target": data.get("target"),
                    "returncode": data.get("returncode"),
                    "duration_seconds": data.get("duration_seconds"),
                    "indicators": data.get("indicators", []),
                })
            return dump({"state_dir": str(STATE_DIR), "runs": rows})

        return text(f"Unknown tool: {name}")
    except (OSError, ValueError, ssl.SSLError, http.client.HTTPException, socket.timeout) as exc:
        return text(f"{type(exc).__name__}: {exc}")


async def main() -> None:
    print(f"php2shell-mcp repo={REPO_DIR} state={STATE_DIR}", file=sys.stderr)
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
