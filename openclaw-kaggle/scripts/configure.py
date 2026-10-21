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
    state_dir = Path(os.environ["OPENCLAW_STATE_DIR"])
    workspace = Path(os.environ["OPENCLAW_WORKSPACE_DIR"])
    model_port = int(os.environ.get("OPENCLAW_MODEL_PORT", "8000"))
    model_alias = os.environ.get("OPENCLAW_MODEL_ALIAS", "WhiteRabbitNeo-13B")
    gateway_port = int(os.environ.get("OPENCLAW_GATEWAY_PORT", "18789"))
    model_ref = f"whiterabbit/{model_alias}"
    return {
        "models": {
            "mode": "replace",
            "providers": {
                "whiterabbit": {
                    "baseUrl": f"http://127.0.0.1:{model_port}/v1",
                    "api": "openai-completions",
                    "auth": "none",
                    "timeoutSeconds": 900,
                    "models": [
                        {
                            "id": model_alias,
                            "name": "WhiteRabbitNeo 13B (Kaggle GPU)",
                            "reasoning": False,
                            "input": ["text"],
                            "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                            "contextWindow": 4096,
                            "contextTokens": 3072,
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
                "models": {model_ref: {"alias": "WhiteRabbit"}},
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
        "commands": {"restart": True},
        "meta": {"deployment": "kaggle", "stateDir": str(state_dir)},
    }


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

    if not config_path.exists():
        atomic_json(config_path, fresh_config())
    ensure_workspace(workspace)
    print(f"config={config_path} workspace={workspace}")


if __name__ == "__main__":
    main()
