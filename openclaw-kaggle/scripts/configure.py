#!/usr/bin/env python3
"""Create a deterministic OpenClaw Kaggle config without replacing restored state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets


def read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def write_dotenv(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(f"{key}={json.dumps(value)}\n" for key, value in sorted(values.items()))
    temporary = path.with_suffix(".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def fresh_config() -> dict:
    workspace = Path(os.environ["OPENCLAW_WORKSPACE_DIR"])
    model_port = int(os.environ.get("OPENCLAW_MODEL_PORT", "8000"))
    model_alias = os.environ.get("OPENCLAW_MODEL_ALIAS", "WhiteRabbitNeo-13B")
    gateway_port = int(os.environ.get("OPENCLAW_GATEWAY_PORT", "18789"))
    model_ref = f"whiterabbit/{model_alias}"
    config = {
        "models": {
            "mode": "replace",
            "providers": {
                "whiterabbit": {
                    "baseUrl": f"http://127.0.0.1:{model_port}/v1",
                    "api": "openai-completions",
                    "apiKey": "local-kaggle-endpoint",
                    "timeoutSeconds": 900,
                    "models": [
                        {
                            "id": model_alias,
                            "name": "WhiteRabbitNeo 13B (Kaggle GPU)",
                            "reasoning": False,
                            "input": ["text"],
                            "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                            "contextWindow": 16384,
                            "contextTokens": 12288,
                            "maxTokens": 1024,
                            "compat": {
                                "supportsTools": True,
                                "supportsStrictMode": False,
                                "supportsTemperature": True,
                                "supportsUsageInStreaming": True,
                                "maxTokensField": "max_tokens",
                            },
                        }
                    ],
                }
            },
        },
        "agents": {
            "defaults": {
                "model": {"primary": model_ref},
                "workspace": str(workspace),
                "timeoutSeconds": 1200,
                "maxConcurrent": 1,
            }
        },
        "gateway": {
            "mode": "local",
            "bind": "loopback",
            "port": gateway_port,
            "auth": {"mode": "token", "token": "${OPENCLAW_GATEWAY_TOKEN}"},
            "controlUi": {
                "allowedOrigins": [
                    f"http://127.0.0.1:{gateway_port}",
                    f"http://localhost:{gateway_port}",
                ]
            },
        },
        "memory": {"search": {"enabled": False}},
        "commands": {"restart": True},
    }
    configure_mcp(config)
    return config


def configure_mcp(config: dict) -> None:
    bundle = Path(os.environ["OPENCLAW_BUNDLE_DIR"])
    state = Path(os.environ["OPENCLAW_SECURITY_STATE_DIR"])
    security_home = Path(os.environ["OPENCLAW_SECURITY_HOME"])
    tools = Path(os.environ["OPENCLAW_SECURITY_TOOLS_DIR"])
    python = os.environ["OPENCLAW_MCP_PYTHON"]
    aircrack_work = state / "aircrack"
    hexstrike_work = state / "hexstrike/work"
    strix_work = state / "strix/work"
    php2shell_work = state / "php2shell/work"
    for directory in (aircrack_work, hexstrike_work, strix_work, php2shell_work):
        directory.mkdir(parents=True, exist_ok=True)
    common_env = {
        "HOME": str(security_home),
        "PATH": f"{os.environ['OPENCLAW_TOOLS_DIR']}/bin:{os.environ.get('PATH', '')}",
    }
    mcp = config.setdefault("mcp", {})
    mcp["sessionIdleTtlMs"] = 3_600_000
    servers = mcp.setdefault("servers", {})
    servers.update(
        {
            "aircrack": {
                "command": python,
                "args": [str(bundle / "mcp/aircrack/server.py")],
                "cwd": str(aircrack_work),
                "env": {
                    **common_env,
                    "AIRCRACK_CAPTURE_DIR": str(state / "aircrack/captures"),
                    "AIRCRACK_WIFI_IFACE": os.environ.get("AIRCRACK_WIFI_IFACE", "wlan0"),
                    "AIRCRACK_MON_IFACE": os.environ.get("AIRCRACK_MON_IFACE", "wlan0mon"),
                },
                "enabled": True,
                "connectionTimeoutMs": 15_000,
                "requestTimeoutMs": 900_000,
                "supportsParallelToolCalls": False,
                "codex": {"defaultToolsApprovalMode": "approve"},
            },
            "hexstrike": {
                "command": python,
                "args": [
                    str(tools / "src/hexstrike/hexstrike_mcp.py"),
                    "--server",
                    f"http://127.0.0.1:{os.environ.get('OPENCLAW_HEXSTRIKE_PORT', '8888')}",
                    "--timeout",
                    "900",
                ],
                "cwd": str(hexstrike_work),
                "env": common_env,
                "enabled": True,
                "connectionTimeoutMs": 30_000,
                "requestTimeoutMs": 900_000,
                "supportsParallelToolCalls": True,
                "codex": {"defaultToolsApprovalMode": "approve"},
            },
            "strix": {
                "command": python,
                "args": [str(bundle / "mcp/strix/server.py")],
                "cwd": str(strix_work),
                "env": {
                    **common_env,
                    "STRIX_BIN": str(tools / "src/strix/.venv/bin/strix"),
                    "STRIX_MCP_DATA": str(state / "strix"),
                    "STRIX_MCP_WORK": str(state / "strix/work"),
                },
                "enabled": True,
                "connectionTimeoutMs": 30_000,
                "requestTimeoutMs": 900_000,
                "supportsParallelToolCalls": False,
                "codex": {"defaultToolsApprovalMode": "approve"},
            },
            "php2shell": {
                "command": python,
                "args": [str(bundle / "mcp/php2shell/server.py")],
                "cwd": str(php2shell_work),
                "env": {
                    **common_env,
                    "PHP2SHELL_REPO": str(tools / "src/php2shell-poc"),
                    "PHP2SHELL_STATE_DIR": str(state / "php2shell"),
                },
                "enabled": True,
                "connectionTimeoutMs": 20_000,
                "requestTimeoutMs": 900_000,
                "supportsParallelToolCalls": False,
                "codex": {"defaultToolsApprovalMode": "approve"},
            },
        }
    )


def ensure_workspace(workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    defaults = {
        "AGENTS.md": "# OpenClaw Workspace\n\nPreserve user files, memory, and existing configuration. Complete requested work and record durable facts in MEMORY.md.\n",
        "MEMORY.md": "# Durable Memory\n\n",
        "USER.md": "# User\n\n",
    }
    for name, content in defaults.items():
        target = workspace / name
        if not target.exists():
            target.write_text(content, encoding="utf-8")
    (workspace / "memory").mkdir(exist_ok=True)


def add_origin(config_path: Path, origin: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    gateway = config.setdefault("gateway", {})
    gateway["publicOrigin"] = origin
    control_ui = gateway.setdefault("controlUi", {})
    origins = control_ui.setdefault("allowedOrigins", [])
    if origin not in origins:
        origins.append(origin)
    atomic_json(config_path, config)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-origin")
    args = parser.parse_args()

    config_path = Path(os.environ["OPENCLAW_CONFIG_PATH"])
    state_dir = Path(os.environ["OPENCLAW_STATE_DIR"])
    workspace = Path(os.environ["OPENCLAW_WORKSPACE_DIR"])
    dotenv_path = state_dir / ".env"

    if args.allow_origin:
        add_origin(config_path, args.allow_origin.rstrip("/"))
        print(f"allowed_origin={args.allow_origin.rstrip('/')}")
        return

    env_values = read_dotenv(dotenv_path)
    token = os.environ.get("OPENCLAW_GATEWAY_TOKEN") or env_values.get("OPENCLAW_GATEWAY_TOKEN")
    if not token:
        token = secrets.token_urlsafe(36)
    env_values["OPENCLAW_GATEWAY_TOKEN"] = token
    write_dotenv(dotenv_path, env_values)

    if config_path.exists():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        configure_mcp(config)
        atomic_json(config_path, config)
    else:
        atomic_json(config_path, fresh_config())
    ensure_workspace(workspace)
    print(f"config={config_path} workspace={workspace}")


if __name__ == "__main__":
    main()
