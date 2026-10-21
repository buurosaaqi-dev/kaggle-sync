# OpenClaw on Kaggle

This kernel runs official OpenClaw `2026.10.5` with pinned Node.js `24.16.0`, serves `WhiteRabbitNeo/WhiteRabbitNeo-13B-v1` locally across the Kaggle GPU allocation, and exposes the authenticated OpenClaw Control UI through a temporary Cloudflare URL.

## Kaggle secrets

Add these under **Kaggle → Settings → Secrets** and enable them for the notebook:

| Secret | Value |
|---|---|
| `GITHUB_TOKEN` | GitHub token with write access to `buurosaaqi-dev/kaggle-sync` |
| `OPENCLAW_BACKUP_KEY` | A long random passphrase kept unchanged between sessions |
| `OPENCLAW_GATEWAY_TOKEN` | Optional fixed browser token; when absent, one is generated and retained inside the encrypted backup |

The notebook prints `OPENCLAW_URL` and `OPENCLAW_GATEWAY_TOKEN` after the model, gateway, and tunnel are ready. Open the URL and paste the token into the Control UI.

## Persistence

At startup, `backups/openclaw-state.enc` is authenticated, decrypted, and restored into `/kaggle/working/openclaw-runtime`. While running, an online SQLite-safe snapshot is encrypted with AES-256-GCM using a 600,000-round PBKDF2-HMAC-SHA256 key and pushed every 15 minutes. A final backup is attempted when the kernel receives a normal stop signal.

The kernel stays active without a Control UI connection by default and has a 10-hour hard limit so the final encrypted backup completes before Kaggle's session ceiling. Set `OPENCLAW_IDLE_MINUTES` to a positive number to enable idle shutdown, and override `OPENCLAW_MAX_RUNTIME_HOURS` when needed.

The archive includes both `state/` and `home/`; model weights, Node binaries, package caches, and operational logs remain outside it and are recreated after a Kaggle reset. Security scan jobs, reports, Aircrack captures, runtime inventories, and repositories live below `state/security/` and `state/repositories/`, so they are encrypted with the rest of the OpenClaw state.

## Native MCP security runtime

Startup brings up the OpenClaw gateway and Cloudflare URL first while model weights initialize. It then verifies checksums for pinned portable binaries, checks out HexStrike, Strix, and PHP2Shell by immutable Git revision, creates an exact Python 3.12.15 environment from `manifests/security-runtime-lock.txt`, and registers Aircrack, HexStrike, Strix, and PHP2Shell under native OpenClaw `mcp.servers`. `openclaw mcp doctor --probe` and `openclaw mcp probe` complete after the public URL is available, and their reports are retained under `state/security/`. Kaggle skips the large distribution APT catalog by default so the gateway can start reliably; set `OPENCLAW_SKIP_SECURITY_APT=0` for a session that needs those additional packages.

PHP2Shell exposes passive advisory, version, header, repository, and lab checks against any target. Its five upstream verification chains run only when every resolved address is loopback; reports persist under `state/security/php2shell/runs/`. The privileged Docker lab from the upstream repository is not assumed inside Kaggle — `php2shell_lab_status` reports whether Docker, Compose, and the loopback listeners at 18080/18081 are actually present.

The public repository contains adapters, manifests, checksums, and installers only. Captures, scan output, API credentials, OpenClaw credentials, and restored state remain in the encrypted archive.

## Versions

- OpenClaw: `2026.10.5`
- Node.js: `24.16.0`
- cloudflared: `2026.10.3`
- Model: `WhiteRabbitNeo/WhiteRabbitNeo-13B-v1`
- MCP Python: `3.12.15`
- MCP SDK: `1.27.0`
- HexStrike: `6.0.0` at `d689933ff579d839c676c82b231f8e98326c5f04`
- Strix: `1.7.0` at `a3c31236bd6305784a501a3102dab0bda83f2317`
- PHP2Shell: `1.0.0` at `6d2168710509a2647545ba78d68afb1e3f745038`
- Aircrack-ng reference: `1:1.7+git20230807.4bf83f1a-3`

The complete binary, Python, and Kali reference pins are in `manifests/security-tools.json`.
