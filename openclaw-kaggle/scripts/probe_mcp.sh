#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/env.sh"

report="$OPENCLAW_SECURITY_STATE_DIR/mcp-doctor.json"
temporary="$report.tmp"
if openclaw mcp doctor --probe --json >"$temporary"; then
  mv "$temporary" "$report"
  echo "mcp_probe=$report"
else
  cat "$temporary" >&2 || true
  rm -f "$temporary"
  exit 1
fi
