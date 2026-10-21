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
python "$OPENCLAW_BUNDLE_DIR/scripts/configure.py"
python "$OPENCLAW_BUNDLE_DIR/scripts/security_inventory.py"

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
"$OPENCLAW_BUNDLE_DIR/scripts/probe_mcp.sh"

python "$OPENCLAW_BUNDLE_DIR/scripts/serve_whiterabbit.py" >"$OPENCLAW_LOG_DIR/model.log" 2>&1 &
MODEL_PID=$!
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

backup_now
(
  while sleep 900; do
    backup_now
  done
) &
BACKUP_LOOP_PID=$!

idle_minutes="${OPENCLAW_IDLE_MINUTES:-30}"
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
    if (( now - last_client_at >= idle_minutes * 60 )); then
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
