#!/usr/bin/env python3
"""Write an exact runtime inventory into encrypted OpenClaw state."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess


COMMANDS = {
    "aircrack-ng": ["aircrack-ng", "--help"],
    "amass": ["amass", "-version"],
    "ffuf": ["ffuf", "-V"],
    "feroxbuster": ["feroxbuster", "--version"],
    "gobuster": ["gobuster", "version"],
    "hashcat": ["hashcat", "--version"],
    "hydra": ["hydra", "-h"],
    "john": ["john", "--list=build-info"],
    "masscan": ["masscan", "--version"],
    "nikto": ["nikto", "-Version"],
    "nmap": ["nmap", "--version"],
    "nuclei": ["nuclei", "-version"],
    "sqlmap": ["sqlmap", "--version"],
    "tcpdump": ["tcpdump", "--version"],
    "tshark": ["tshark", "--version"],
}


def version(argv: list[str]) -> dict:
    path = shutil.which(argv[0])
    if not path:
        return {"available": False}
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
        lines = (result.stdout + "\n" + result.stderr).strip().splitlines()
        return {"available": True, "path": path, "version": lines[0][:500] if lines else "unknown"}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": True, "path": path, "version": f"probe failed: {exc}"}


def main() -> None:
    state = Path(os.environ["OPENCLAW_SECURITY_STATE_DIR"])
    output = state / "inventory.json"
    data = {
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "manifest": json.loads((Path(os.environ["OPENCLAW_BUNDLE_DIR"]) / "manifests/security-tools.json").read_text()),
        "installed": {name: version(argv) for name, argv in COMMANDS.items()},
    }
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, output)
    print(f"security_inventory={output}")


if __name__ == "__main__":
    main()
