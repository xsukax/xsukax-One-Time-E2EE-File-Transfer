# xsukax-One-Time-E2EE-File-Transfer
Self-hosted, single-file PHP app for one-time E2EE file sharing. Files are encrypted client-side with AES-256-GCM (PBKDF2 × 200k rounds) before upload — the server never sees plaintext. Auto-deletes on first download or after 30 minutes. Zero dependencies, zero database.
