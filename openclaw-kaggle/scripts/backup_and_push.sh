#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/env.sh"

LOCK_FILE="$OPENCLAW_WORK_ROOT/openclaw-backup.lock"
mkdir -p "$(dirname -- "$LOCK_FILE")" "$(dirname -- "$OPENCLAW_BACKUP_FILE")"
exec 9>"$LOCK_FILE"
if ! flock --nonblock 9; then
  echo "backup already running"
  exit 0
fi

if [[ -z "${OPENCLAW_BACKUP_KEY:-}" ]]; then
  echo "OPENCLAW_BACKUP_KEY is not set; encrypted backup skipped" >&2
  exit 2
fi

cd "$KAGGLE_SYNC_ROOT"
git config user.name "OpenClaw Kaggle Backup"
git config user.email "openclaw-kaggle@users.noreply.github.com"

if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  git pull --rebase --autostash origin main
fi

python "$OPENCLAW_BUNDLE_DIR/scripts/state_archive.py" backup \
  --runtime-root "$OPENCLAW_RUNTIME_ROOT" \
  --archive "$OPENCLAW_BACKUP_FILE"

python - "$OPENCLAW_BACKUP_FILE" "$OPENCLAW_BACKUP_MANIFEST" <<'PY'
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

archive = Path(sys.argv[1])
manifest = Path(sys.argv[2])
digest = hashlib.sha256()
with archive.open("rb") as stream:
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
payload = {
    "format": "openclaw-kaggle-backup-v1",
    "cipher": "AES-256-GCM",
    "kdf": "PBKDF2-HMAC-SHA256",
    "kdfIterations": 600000,
    "archive": archive.name,
    "bytes": archive.stat().st_size,
    "sha256": digest.hexdigest(),
    "openclawVersion": "2026.10.5",
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
temporary = manifest.with_suffix(".tmp")
temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.replace(temporary, manifest)
PY

git add -- "$OPENCLAW_BACKUP_FILE" "$OPENCLAW_BACKUP_MANIFEST"
if git diff --cached --quiet; then
  echo "encrypted state is unchanged"
  exit 0
fi
git commit -m "OpenClaw encrypted state backup $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "GITHUB_TOKEN is not set; backup committed locally only" >&2
  exit 3
fi

askpass="$(mktemp "$OPENCLAW_WORK_ROOT/openclaw-askpass.XXXXXX")"
cleanup() { rm -f "$askpass"; }
trap cleanup EXIT
cat >"$askpass" <<'SH'
#!/usr/bin/env sh
case "$1" in
  *Username*) printf '%s\n' x-access-token ;;
  *) printf '%s\n' "$GITHUB_TOKEN" ;;
esac
SH
chmod 0700 "$askpass"

export GIT_ASKPASS="$askpass"
export GIT_TERMINAL_PROMPT=0
git push origin HEAD:main
echo "encrypted OpenClaw state pushed to GitHub"
