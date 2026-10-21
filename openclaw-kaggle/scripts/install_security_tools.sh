#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/env.sh"

MANIFEST="$OPENCLAW_BUNDLE_DIR/manifests/security-tools.json"
LOCK_HASH="$(sha256sum "$MANIFEST" "$OPENCLAW_BUNDLE_DIR/manifests/security-runtime-requirements.txt" | sha256sum | cut -d' ' -f1)"
SECURITY_ROOT="$OPENCLAW_TOOLS_DIR/security"
SOURCE_ROOT="$SECURITY_ROOT/src"
VENV="$SECURITY_ROOT/mcp-venv"
MARKER="$SECURITY_ROOT/.installed-$LOCK_HASH"
mkdir -p "$SOURCE_ROOT" "$OPENCLAW_TOOLS_DIR/bin" "$OPENCLAW_SECURITY_STATE_DIR"

download() {
  local url=$1 output=$2 checksum=$3
  if [[ ! -f "$output" ]] || ! printf '%s  %s\n' "$checksum" "$output" | sha256sum --check --status; then
    curl --fail --location --retry 5 --retry-all-errors --connect-timeout 20 --output "$output.part" "$url"
    printf '%s  %s\n' "$checksum" "$output.part" | sha256sum --check --status
    mv "$output.part" "$output"
  fi
}

install_archive_binary() {
  local name=$1 url=$2 checksum=$3 member=$4
  local archive="$SECURITY_ROOT/$(basename "$url")" temporary
  download "$url" "$archive" "$checksum"
  temporary="$(mktemp -d "$SECURITY_ROOT/extract.XXXXXX")"
  case "$archive" in
    *.zip) unzip -q "$archive" -d "$temporary" ;;
    *.tar.gz) tar -xzf "$archive" -C "$temporary" ;;
  esac
  local found
  found="$(find "$temporary" -type f -path "*/$member" -o -type f -name "$member" | head -n 1)"
  install -m 0755 "$found" "$OPENCLAW_TOOLS_DIR/bin/$name"
  rm -rf "$temporary"
}

if [[ ! -f "$MARKER" ]]; then
  if [[ "${OPENCLAW_SKIP_SECURITY_APT:-0}" != 1 ]] && command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections 2>/dev/null || true
    candidates=(
      aircrack-ng nmap masscan sqlmap nikto dirb hydra john hashcat tshark tcpdump
      whois dnsutils smbclient binutils file git curl unzip xz-utils python3-venv
    )
    packages=()
    for package in "${candidates[@]}"; do
      apt-cache show "$package" >/dev/null 2>&1 && packages+=("$package")
    done
    apt-get install -y --no-install-recommends "${packages[@]}"
    apt-get clean
    rm -rf /var/lib/apt/lists/*
  fi

  install_archive_binary ffuf \
    https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5 ffuf
  install_archive_binary nuclei \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip \
    cd4ea43c88b50af8ab96eb6ad3fb4debd8e9d51efaff4d4c2d99106041578943 nuclei
  install_archive_binary gobuster \
    https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz \
    c8a8c6a966eeb011d682a0ef2305a3e3a86b8b3fabe744350c00a766cc0f8021 gobuster
  install_archive_binary feroxbuster \
    https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.tar.gz \
    7985c00e6803b0f25d5e9139f7472279f3f4d891429627a5cedc629e53992d80 feroxbuster
  install_archive_binary amass \
    https://github.com/owasp-amass/amass/releases/download/v5.1.1/amass_linux_amd64.tar.gz \
    5e22b5f0239e7eb79439d60d43d3cd20dca2478588bc2242e91ab0c4f8fa40dd amass

  rm -rf "$SOURCE_ROOT/hexstrike" "$SOURCE_ROOT/strix"
  git init -q "$SOURCE_ROOT/hexstrike"
  git -C "$SOURCE_ROOT/hexstrike" remote add origin https://github.com/0x4m4/hexstrike-ai.git
  git -C "$SOURCE_ROOT/hexstrike" fetch -q --depth 1 origin d689933ff579d839c676c82b231f8e98326c5f04
  git -C "$SOURCE_ROOT/hexstrike" checkout -q --detach FETCH_HEAD
  [[ "$(git -C "$SOURCE_ROOT/hexstrike" rev-parse HEAD)" == d689933ff579d839c676c82b231f8e98326c5f04 ]]
  python - "$SOURCE_ROOT/hexstrike/hexstrike_server.py" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
needle = 'app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)'
if needle not in source:
    raise SystemExit("HexStrike bind statement changed upstream")
path.write_text(source.replace(needle, 'app.run(host=API_HOST, port=API_PORT, debug=DEBUG_MODE)'), encoding="utf-8")
PY

  uv_archive="$SECURITY_ROOT/uv-x86_64-unknown-linux-gnu.tar.gz"
  download https://github.com/astral-sh/uv/releases/download/0.13.4/uv-x86_64-unknown-linux-gnu.tar.gz \
    "$uv_archive" 2b428396f12572d4429cf210ca234dd599a33b3af0958a4d5ed569d63e3f344f
  uv_temp="$(mktemp -d "$SECURITY_ROOT/uv.XXXXXX")"
  tar -xzf "$uv_archive" -C "$uv_temp"
  install -m 0755 "$uv_temp"/*/uv "$OPENCLAW_TOOLS_DIR/bin/uv"
  install -m 0755 "$uv_temp"/*/uvx "$OPENCLAW_TOOLS_DIR/bin/uvx"
  rm -rf "$uv_temp"

  "$OPENCLAW_TOOLS_DIR/bin/uv" python install 3.12
  rm -rf "$VENV"
  "$OPENCLAW_TOOLS_DIR/bin/uv" venv --python 3.12 "$VENV"
  "$OPENCLAW_TOOLS_DIR/bin/uv" pip install --python "$VENV/bin/python" \
    --requirement "$OPENCLAW_BUNDLE_DIR/manifests/security-runtime-requirements.txt"

  git init -q "$SOURCE_ROOT/strix"
  git -C "$SOURCE_ROOT/strix" remote add origin https://github.com/usestrix/strix.git
  git -C "$SOURCE_ROOT/strix" fetch -q --depth 1 origin a3c31236bd6305784a501a3102dab0bda83f2317
  git -C "$SOURCE_ROOT/strix" checkout -q --detach FETCH_HEAD
  [[ "$(git -C "$SOURCE_ROOT/strix" rev-parse HEAD)" == a3c31236bd6305784a501a3102dab0bda83f2317 ]]
  (cd "$SOURCE_ROOT/strix" && "$OPENCLAW_TOOLS_DIR/bin/uv" sync --frozen --no-dev)

  rm -f "$SECURITY_ROOT"/.installed-*
  touch "$MARKER"
fi

python "$OPENCLAW_BUNDLE_DIR/scripts/security_inventory.py"
