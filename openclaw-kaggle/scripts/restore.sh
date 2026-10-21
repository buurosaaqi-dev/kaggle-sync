#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/env.sh"

if [[ ! -s "$OPENCLAW_BACKUP_FILE" ]]; then
  echo "no encrypted OpenClaw backup found; initializing fresh state"
  exit 0
fi
if [[ -z "${OPENCLAW_BACKUP_KEY:-}" ]]; then
  echo "OPENCLAW_BACKUP_KEY is required to restore the encrypted state" >&2
  exit 2
fi

if [[ -s "$OPENCLAW_BACKUP_MANIFEST" ]]; then
  python - "$OPENCLAW_BACKUP_FILE" "$OPENCLAW_BACKUP_MANIFEST" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

archive = Path(sys.argv[1])
manifest = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
digest = hashlib.sha256()
with archive.open("rb") as stream:
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
if digest.hexdigest() != manifest["sha256"]:
    raise SystemExit("encrypted backup SHA-256 does not match manifest")
if archive.stat().st_size != manifest["bytes"]:
    raise SystemExit("encrypted backup size does not match manifest")
PY
fi

python "$OPENCLAW_BUNDLE_DIR/scripts/state_archive.py" restore \
  --runtime-root "$OPENCLAW_RUNTIME_ROOT" \
  --archive "$OPENCLAW_BACKUP_FILE"
