# Encrypted runtime state

`openclaw-state.enc` is produced inside Kaggle and committed automatically. It contains the OpenClaw state directory, workspace, sessions, credentials, and home data as a compressed AES-256-GCM archive. The encryption key exists only in the Kaggle `OPENCLAW_BACKUP_KEY` secret.

`manifest.json` records the ciphertext hash, size, format, and timestamp. Never commit the backup key or a decrypted archive.
