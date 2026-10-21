#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/env.sh"

NODE_VERSION=24.16.0
NODE_ARCHIVE="node-v${NODE_VERSION}-linux-x64.tar.xz"
NODE_SHA256=d804845d34eddc21dc1092b519d643ef40b1f58ec5dec5c22b1f4bd8fabde6c9
NODE_DIR="$OPENCLAW_TOOLS_DIR/node-v${NODE_VERSION}-linux-x64"
OPENCLAW_VERSION=2026.10.5
CLOUDFLARED_VERSION=2026.10.3
CLOUDFLARED_SHA256=053b80b0a23031a038fdbf3c073f59f82b8f1f152aa67971d7383ffafc0dbab0

download() {
  local url=$1 output=$2
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 20 \
    --output "$output.part" "$url"
  mv "$output.part" "$output"
}

if [[ ! -x "$NODE_DIR/bin/node" ]]; then
  archive="$OPENCLAW_TOOLS_DIR/$NODE_ARCHIVE"
  download "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_ARCHIVE}" "$archive"
  printf '%s  %s\n' "$NODE_SHA256" "$archive" | sha256sum --check --status
  tar -xJf "$archive" -C "$OPENCLAW_TOOLS_DIR"
  rm -f "$archive"
fi

export PATH="$NODE_DIR/bin:$OPENCLAW_TOOLS_DIR/npm/bin:$OPENCLAW_TOOLS_DIR/bin:$PATH"

installed_version=""
if [[ -x "$OPENCLAW_TOOLS_DIR/npm/bin/openclaw" ]]; then
  installed_version="$($OPENCLAW_TOOLS_DIR/npm/bin/openclaw --version 2>/dev/null | tail -n 1 || true)"
fi
if [[ "$installed_version" != *"$OPENCLAW_VERSION"* ]]; then
  npm_version="$(npm --version)"
  npm_major="${npm_version%%.*}"
  npm_minor="$(cut -d. -f2 <<<"$npm_version")"
  install_args=(install --global --prefix "$OPENCLAW_TOOLS_DIR/npm" "openclaw@$OPENCLAW_VERSION")
  if (( npm_major >= 12 || (npm_major == 11 && npm_minor >= 16) )); then
    install_args+=(--allow-scripts=openclaw)
  fi
  npm "${install_args[@]}"
fi

cloudflared="$OPENCLAW_TOOLS_DIR/bin/cloudflared"
if [[ ! -x "$cloudflared" ]] || [[ "$($cloudflared --version 2>/dev/null || true)" != *"$CLOUDFLARED_VERSION"* ]]; then
  download "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-amd64" "$cloudflared"
  printf '%s  %s\n' "$CLOUDFLARED_SHA256" "$cloudflared" | sha256sum --check --status
  chmod 0755 "$cloudflared"
fi

if [[ "${OPENCLAW_SKIP_MODEL_DEPS:-0}" != 1 ]]; then
  python -m pip install --quiet --upgrade \
    'transformers>=4.52,<5' \
    'accelerate>=1.6,<2' \
    'bitsandbytes>=0.45,<1' \
    'fastapi>=0.115,<1' \
    'uvicorn>=0.34,<1' \
    'pydantic>=2.10,<3' \
    'cryptography>=44,<47'
fi

"$OPENCLAW_BUNDLE_DIR/scripts/install_security_tools.sh"

node --version
openclaw --version
cloudflared --version
