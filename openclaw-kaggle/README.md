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

The archive includes both `state/` and `home/`; model weights, Node binaries, package caches, and operational logs remain outside it and are recreated after a Kaggle reset.

## Versions

- OpenClaw: `2026.10.5`
- Node.js: `24.16.0`
- cloudflared: `2026.10.3`
- Model: `WhiteRabbitNeo/WhiteRabbitNeo-13B-v1`
