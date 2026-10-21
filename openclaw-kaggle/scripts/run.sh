#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/env.sh"

MODEL_PID=""
GATEWAY_PID=""
TUNNEL_PID=""
HEXSTRIKE_PID=""
BACKUP_LOOP_PID=""
IDLE_WATCH_PID=""

backup_now() {
  if [[ -n "${OPENCLAW_BACKUP_KEY:-}" ]]; then
    "$OPENCLAW_BUNDLE_DIR/scripts/backup_and_push.sh" || true
  fi
}

cleanup() {
  trap - EXIT INT TERM
  [[ -n "$BACKUP_LOOP_PID" ]] && kill "$BACKUP_LOOP_PID" 2>/dev/null || true
  [[ -n "$IDLE_WATCH_PID" ]] && kill "$IDLE_WATCH_PID" 2>/dev/null || true
  backup_now
  [[ -n "$TUNNEL_PID" ]] && kill "$TUNNEL_PID" 2>/dev/null || true
  [[ -n "$GATEWAY_PID" ]] && kill "$GATEWAY_PID" 2>/dev/null || true
  [[ -n "$MODEL_PID" ]] && kill "$MODEL_PID" 2>/dev/null || true
  [[ -n "$HEXSTRIKE_PID" ]] && kill "$HEXSTRIKE_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$OPENCLAW_BUNDLE_DIR/scripts/bootstrap.sh"
"$OPENCLAW_BUNDLE_DIR/scripts/restore.sh"
OPENCLAW_DEFER_MCP=1 python "$OPENCLAW_BUNDLE_DIR/scripts/configure.py"

OPENCLAW_GATEWAY_TOKEN="$(python - "$OPENCLAW_STATE_DIR/.env" <<'PY'
import json
from pathlib import Path
import sys

for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if raw.startswith("OPENCLAW_GATEWAY_TOKEN="):
        print(json.loads(raw.split("=", 1)[1]))
        break
else:
    raise SystemExit("OPENCLAW_GATEWAY_TOKEN is missing from the state .env")
PY
)"
export OPENCLAW_GATEWAY_TOKEN

# Start model loading without holding the public gateway behind it. The UI and
# tunnel become reachable while model weights initialize on the GPU.
python "$OPENCLAW_BUNDLE_DIR/scripts/serve_whiterabbit.py" >"$OPENCLAW_LOG_DIR/model.log" 2>&1 &
MODEL_PID=$!

openclaw gateway run --bind loopback --port "$OPENCLAW_GATEWAY_PORT" \
  >"$OPENCLAW_LOG_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
for _ in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:$OPENCLAW_GATEWAY_PORT/" >/dev/null; then
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    tail -n 100 "$OPENCLAW_LOG_DIR/gateway.log" >&2
    exit 1
  fi
  sleep 2
done
curl --fail --silent "http://127.0.0.1:$OPENCLAW_GATEWAY_PORT/" >/dev/null

cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$OPENCLAW_GATEWAY_PORT" \
  >"$OPENCLAW_LOG_DIR/tunnel.log" 2>&1 &
TUNNEL_PID=$!
tunnel_url=""
for _ in $(seq 1 60); do
  tunnel_url="$(grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$OPENCLAW_LOG_DIR/tunnel.log" | head -n 1 || true)"
  [[ -n "$tunnel_url" ]] && break
  if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
    cat "$OPENCLAW_LOG_DIR/tunnel.log" >&2
    exit 1
  fi
  sleep 2
done
if [[ -z "$tunnel_url" ]]; then
  cat "$OPENCLAW_LOG_DIR/tunnel.log" >&2
  exit 1
fi

python "$OPENCLAW_BUNDLE_DIR/scripts/configure.py" --allow-origin "$tunnel_url"
printf '\nOPENCLAW_URL=%s\nOPENCLAW_GATEWAY_TOKEN=%s\n\n' "$tunnel_url" "$OPENCLAW_GATEWAY_TOKEN"

python - "$OPENCLAW_SECURITY_STATE_DIR/runtime-access.json" "$tunnel_url" "$OPENCLAW_GATEWAY_TOKEN" <<'PY'
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

target = Path(sys.argv[1])
payload = {
    "url": sys.argv[2],
    "gatewayToken": sys.argv[3],
    "gatewayPort": int(os.environ["OPENCLAW_GATEWAY_PORT"]),
    "modelPort": int(os.environ["OPENCLAW_MODEL_PORT"]),
    "hexstrikePort": int(os.environ["OPENCLAW_HEXSTRIKE_PORT"]),
    "startedAt": datetime.now(timezone.utc).isoformat(),
    "status": "gateway-ready-model-loading",
}
temporary = target.with_suffix(".tmp")
temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
os.replace(temporary, target)
PY

backup_now
(
  while sleep 900; do
    backup_now
  done
) &
BACKUP_LOOP_PID=$!

echo "Initializing native MCP security runtime after gateway startup..."
"$OPENCLAW_BUNDLE_DIR/scripts/install_security_tools.sh"
python "$OPENCLAW_BUNDLE_DIR/scripts/configure.py"

hexstrike_work="$OPENCLAW_SECURITY_STATE_DIR/hexstrike/work"
mkdir -p "$hexstrike_work"
(
  cd "$hexstrike_work"
  exec env \
    HOME="$OPENCLAW_SECURITY_HOME" \
    HEXSTRIKE_HOST=127.0.0.1 \
    HEXSTRIKE_PORT="$OPENCLAW_HEXSTRIKE_PORT" \
    "$OPENCLAW_MCP_PYTHON" \
    "$OPENCLAW_SECURITY_TOOLS_DIR/src/hexstrike/hexstrike_server.py" \
    --port "$OPENCLAW_HEXSTRIKE_PORT"
) >"$OPENCLAW_LOG_DIR/hexstrike.log" 2>&1 &
HEXSTRIKE_PID=$!
for _ in $(seq 1 90); do
  if curl --fail --silent "http://127.0.0.1:$OPENCLAW_HEXSTRIKE_PORT/health" >/dev/null; then
    break
  fi
  if ! kill -0 "$HEXSTRIKE_PID" 2>/dev/null; then
    tail -n 100 "$OPENCLAW_LOG_DIR/hexstrike.log" >&2
    exit 1
  fi
  sleep 2
done
curl --fail --silent "http://127.0.0.1:$OPENCLAW_HEXSTRIKE_PORT/health" >/dev/null

# Reload the gateway once so the newly enabled MCP catalog is active even on
# OpenClaw builds that do not hot-reload mcp.servers changes.
kill "$GATEWAY_PID" 2>/dev/null || true
wait "$GATEWAY_PID" 2>/dev/null || true
openclaw gateway run --bind loopback --port "$OPENCLAW_GATEWAY_PORT" \
  >>"$OPENCLAW_LOG_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
for _ in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:$OPENCLAW_GATEWAY_PORT/" >/dev/null; then
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    tail -n 100 "$OPENCLAW_LOG_DIR/gateway.log" >&2
    exit 1
  fi
  sleep 2
done
curl --fail --silent "http://127.0.0.1:$OPENCLAW_GATEWAY_PORT/" >/dev/null
"$OPENCLAW_BUNDLE_DIR/scripts/probe_mcp.sh"
echo "OPENCLAW_MCP_READY=aircrack,hexstrike,strix,php2shell"

for _ in $(seq 1 180); do
  if curl --fail --silent "http://127.0.0.1:$OPENCLAW_MODEL_PORT/health" >/dev/null; then
    break
  fi
  if ! kill -0 "$MODEL_PID" 2>/dev/null; then
    tail -n 100 "$OPENCLAW_LOG_DIR/model.log" >&2
    exit 1
  fi
  sleep 5
done
curl --fail --silent "http://127.0.0.1:$OPENCLAW_MODEL_PORT/health"
python - "$OPENCLAW_SECURITY_STATE_DIR/runtime-access.json" <<'PY'
import json
import os
from pathlib import Path
import sys

target = Path(sys.argv[1])
payload = json.loads(target.read_text(encoding="utf-8"))
payload["status"] = "ready"
temporary = target.with_suffix(".tmp")
temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
os.replace(temporary, target)
PY
echo "OPENCLAW_READY=$tunnel_url"

idle_minutes="${OPENCLAW_IDLE_MINUTES:-0}"
max_runtime_hours="${OPENCLAW_MAX_RUNTIME_HOURS:-10}"
(
  started_at="$(date +%s)"
  last_client_at="$started_at"
  while sleep 60; do
    now="$(date +%s)"
    if python - "$OPENCLAW_GATEWAY_PORT" <<'PY'
from pathlib import Path
import sys

port = int(sys.argv[1])
for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
    if not table.exists():
        continue
    for line in table.read_text().splitlines()[1:]:
        fields = line.split()
        local_port = int(fields[1].rsplit(":", 1)[1], 16)
        state = fields[3]
        if local_port == port and state == "01":
            raise SystemExit(0)
raise SystemExit(1)
PY
    then
      last_client_at="$now"
    fi
    if (( idle_minutes > 0 && now - last_client_at >= idle_minutes * 60 )); then
      echo "No Control UI connection for ${idle_minutes} minutes; saving state and stopping GPU session."
      kill -TERM $$
      exit 0
    fi
    if (( now - started_at >= max_runtime_hours * 3600 )); then
      echo "Maximum runtime of ${max_runtime_hours} hours reached; saving state and stopping GPU session."
      kill -TERM $$
      exit 0
    fi
  done
) &
IDLE_WATCH_PID=$!

wait "$GATEWAY_PID"
