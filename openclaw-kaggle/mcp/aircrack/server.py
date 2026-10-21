#!/usr/bin/env python3
"""Portable Aircrack-ng MCP server with persistent capture storage."""

from __future__ import annotations

import asyncio
import gzip
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server


WIFI_IFACE = os.environ.get("AIRCRACK_WIFI_IFACE", "wlan0")
MON_IFACE = os.environ.get("AIRCRACK_MON_IFACE", f"{WIFI_IFACE}mon")
CAPTURE_DIR = Path(os.environ.get("AIRCRACK_CAPTURE_DIR", Path.home() / "aircrack-captures"))
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
app = Server("aircrack-ng-server")


def privileged(argv: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return argv
    sudo = shutil.which("sudo")
    return [sudo, "-n", *argv] if sudo else argv


def run(argv: list[str], timeout: int = 30) -> dict:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
            "success": result.returncode == 0,
        }
    except FileNotFoundError as exc:
        return {"stdout": "", "stderr": f"command unavailable: {exc.filename}", "returncode": 127, "success": False}
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        error = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {"stdout": output.strip(), "stderr": (error or "command timed out").strip(), "returncode": 124, "success": False}


def text(value: str) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=value)]


def validate_mac(value: str, label: str) -> str:
    if not MAC_RE.fullmatch(value):
        raise ValueError(f"{label} must be a MAC address in XX:XX:XX:XX:XX:XX form")
    return value.upper()


def validate_channel(value: int) -> int:
    channel = int(value)
    if not 1 <= channel <= 196:
        raise ValueError("channel must be between 1 and 196")
    return channel


def capture_prefix(value: str) -> Path:
    name = Path(value).name
    if not NAME_RE.fullmatch(name):
        raise ValueError("capture_file must be a plain file name using letters, numbers, dot, dash, or underscore")
    return CAPTURE_DIR / name


def monitor_active() -> bool:
    result = run(["iw", "dev", MON_IFACE, "info"])
    return result["success"] and "type monitor" in result["stdout"]


def interfaces() -> str:
    result = run(["iw", "dev"])
    return result["stdout"] or result["stderr"] or "No wireless interface is exposed by this runtime."


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    empty = {"type": "object", "properties": {}, "required": []}
    return [
        types.Tool(name="start_monitor", description="Start a virtual monitor interface while leaving the managed interface up", inputSchema=empty),
        types.Tool(name="stop_monitor", description="Stop and remove the virtual monitor interface", inputSchema=empty),
        types.Tool(
            name="scan_networks",
            description="Scan nearby Wi-Fi networks for five seconds",
            inputSchema={"type": "object", "properties": {"channel": {"type": "integer", "minimum": 1, "maximum": 196}}, "required": []},
        ),
        types.Tool(
            name="capture_handshake",
            description="Start a sixty-second WPA capture into persistent storage",
            inputSchema={
                "type": "object",
                "properties": {
                    "bssid": {"type": "string"},
                    "channel": {"type": "integer", "minimum": 1, "maximum": 196},
                    "capture_file": {"type": "string", "default": "capture"},
                },
                "required": ["bssid", "channel"],
            },
        ),
        types.Tool(
            name="deauth_attack",
            description="Transmit deauthentication frames through the monitor interface",
            inputSchema={
                "type": "object",
                "properties": {
                    "bssid": {"type": "string"},
                    "client": {"type": "string", "default": "FF:FF:FF:FF:FF:FF"},
                    "count": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 10},
                },
                "required": ["bssid"],
            },
        ),
        types.Tool(
            name="crack_password",
            description="Run Aircrack-ng against a saved capture and wordlist",
            inputSchema={
                "type": "object",
                "properties": {"capture_file": {"type": "string"}, "wordlist": {"type": "string"}, "bssid": {"type": "string"}},
                "required": ["capture_file"],
            },
        ),
        types.Tool(name="wifi_status", description="Show wireless interfaces, monitor state, binaries, and persistent capture count", inputSchema=empty),
        types.Tool(name="list_captures", description="List files in persistent Aircrack capture storage", inputSchema=empty),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        if name == "start_monitor":
            if monitor_active():
                return text(f"Monitor mode is already active on {MON_IFACE}.")
            if not Path(f"/sys/class/net/{WIFI_IFACE}").exists():
                return text(f"Wireless interface {WIFI_IFACE} is unavailable in this runtime. Offline capture analysis remains available in {CAPTURE_DIR}.")
            result = run(privileged(["iw", "dev", WIFI_IFACE, "interface", "add", MON_IFACE, "type", "monitor"]))
            if result["success"]:
                result = run(privileged(["ip", "link", "set", MON_IFACE, "up"]))
            elif shutil.which("airmon-ng"):
                result = run(privileged(["airmon-ng", "start", WIFI_IFACE]), timeout=60)
            return text((result["stdout"] or result["stderr"]) + f"\n\nInterfaces:\n{interfaces()}")

        if name == "stop_monitor":
            down = run(privileged(["ip", "link", "set", MON_IFACE, "down"]))
            removed = run(privileged(["iw", "dev", MON_IFACE, "del"]))
            if not removed["success"] and shutil.which("airmon-ng"):
                removed = run(privileged(["airmon-ng", "stop", MON_IFACE]), timeout=60)
            detail = removed["stdout"] or removed["stderr"] or down["stderr"]
            return text(f"Monitor interface {MON_IFACE} stopped.\n{detail}".strip())

        if name == "scan_networks":
            channel = arguments.get("channel")
            if channel is not None:
                channel = validate_channel(channel)
            if not monitor_active():
                if not shutil.which("nmcli"):
                    return text("No monitor interface or NetworkManager scanner is available in this runtime.")
                result = run(privileged(["nmcli", "dev", "wifi", "list", "--rescan", "yes"]), timeout=20)
                return text(result["stdout"] or result["stderr"])
            with tempfile.TemporaryDirectory(dir=CAPTURE_DIR, prefix="scan-") as temporary:
                prefix = Path(temporary) / "networks"
                argv = ["timeout", "5", "airodump-ng"]
                if channel:
                    argv.extend(["--channel", str(channel)])
                argv.extend(["--output-format", "csv", "--write", str(prefix), MON_IFACE])
                run(privileged(argv), timeout=10)
                csv_path = prefix.with_name(prefix.name + "-01.csv")
                output = csv_path.read_text(encoding="utf-8", errors="replace") if csv_path.exists() else "No networks were captured."
                return text("\n".join(output.splitlines()[:80]))

        if name == "capture_handshake":
            if not monitor_active():
                return text(f"Monitor interface {MON_IFACE} is not active.")
            bssid = validate_mac(arguments["bssid"], "bssid")
            channel = validate_channel(arguments["channel"])
            prefix = capture_prefix(arguments.get("capture_file", "capture"))
            log = prefix.with_suffix(".log").open("ab")
            argv = privileged([
                "timeout", "60", "airodump-ng", "--channel", str(channel), "--bssid", bssid,
                "--write", str(prefix), "--output-format", "pcap", MON_IFACE,
            ])
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            log.close()
            return text(f"Capture started with PID {process.pid}; output prefix: {prefix}")

        if name == "deauth_attack":
            if not monitor_active():
                return text(f"Monitor interface {MON_IFACE} is not active.")
            bssid = validate_mac(arguments["bssid"], "bssid")
            client = validate_mac(arguments.get("client", "FF:FF:FF:FF:FF:FF"), "client")
            count = int(arguments.get("count", 10))
            if not 1 <= count <= 1000:
                raise ValueError("count must be between 1 and 1000")
            result = run(privileged(["aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", client, MON_IFACE]), timeout=120)
            return text(result["stdout"] or result["stderr"])

        if name == "crack_password":
            capture = Path(arguments["capture_file"]).expanduser()
            if not capture.is_absolute():
                capture = CAPTURE_DIR / capture
            wordlist = Path(arguments.get("wordlist", "/usr/share/wordlists/rockyou.txt")).expanduser()
            if wordlist.suffix == ".gz":
                expanded = CAPTURE_DIR / wordlist.stem
                if not expanded.exists():
                    with gzip.open(wordlist, "rb") as source, expanded.open("wb") as destination:
                        shutil.copyfileobj(source, destination)
                wordlist = expanded
            if not capture.is_file():
                raise ValueError(f"capture file does not exist: {capture}")
            if not wordlist.is_file():
                raise ValueError(f"wordlist does not exist: {wordlist}")
            argv = ["aircrack-ng"]
            if arguments.get("bssid"):
                argv.extend(["-b", validate_mac(arguments["bssid"], "bssid")])
            argv.extend(["-w", str(wordlist), str(capture)])
            result = run(argv, timeout=900)
            return text(result["stdout"] or result["stderr"])

        if name == "wifi_status":
            binaries = {tool: bool(shutil.which(tool)) for tool in ("aircrack-ng", "airodump-ng", "aireplay-ng", "iw", "nmcli")}
            captures = sum(1 for path in CAPTURE_DIR.iterdir() if path.is_file())
            return text(f"monitor_active={monitor_active()}\nwifi_interface={WIFI_IFACE}\nmonitor_interface={MON_IFACE}\nbinaries={binaries}\ncaptures={captures}\ncapture_dir={CAPTURE_DIR}\n\n{interfaces()}")

        if name == "list_captures":
            files = sorted((path for path in CAPTURE_DIR.iterdir() if path.is_file()), key=lambda path: path.name)
            if not files:
                return text(f"No capture files in {CAPTURE_DIR}.")
            return text("\n".join(f"{path.name}\t{path.stat().st_size} bytes" for path in files))

        return text(f"Unknown tool: {name}")
    except (OSError, ValueError) as exc:
        return text(f"{type(exc).__name__}: {exc}")


async def main() -> None:
    print(f"aircrack-mcp capture_dir={CAPTURE_DIR}", file=sys.stderr)
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
