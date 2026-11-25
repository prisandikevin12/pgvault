# PGVault

Zero-knowledge, streaming PostgreSQL backup, automated Docker restore verification, retention pruning, and dark observability control plane—written in Go & Next.js.

## 2-Step Quickstart

```bash
git clone https://github.com/prisandikevin12/pgvault.git && cd pgvault
./quickstart.sh
```

`quickstart.sh` automatically:
1. Generates a secure local `.env` (`PGVAULT_KEK_HEX`, `PGVAULT_API_KEY`, random PostgreSQL password, and `DOCKER_GID`) if one does not exist.
2. Builds and starts the complete stack (`app-db`, `target-db` demo database, LocalStack S3 with auto-created `pgvault-backups` bucket, `api`, `worker`, and `web`).
3. Pre-configures the dashboard (`http://localhost:3000`) to auto-connect and authenticate cleanly—no manual setup required.

---

## Key Features

- **Zero-Disk Streaming Backups (`internal/pgdump`)**: Pipes `pg_dump --format=custom --no-owner --no-privileges` directly through in-memory `io.Pipe` -> AES-256-GCM encryption -> S3 multipart upload. Plaintext dumps never touch disk.
- **Envelope Encryption & Chunked AEAD (`internal/crypto`)**: Fresh 32-byte random DEK per backup wrapped with your 32-byte KEK (`AES-256-GCM`), streaming 64 KiB `PGV1` chunks with header AAD authentication, per-chunk nonces (`noncePrefix || chunkIndex || finalFlag`), truncation/reordering protection, and on-the-fly SHA-256 checksums.
- **Automated Ephemeral Docker Restore Verification (`internal/verifier`)**: Launches an isolated `postgres:<major>-alpine` container (`NetworkMode: "none"`, CPU/Memory/PID limits), streams S3 -> `DecryptStream` -> `pg_restore --exit-on-error`, verifies restored table counts, runs optional read-only sanity queries (`BEGIN READ ONLY` + `5s` timeout), and guarantees container + volume cleanup.
- **Auto-Scheduler, Stale Lease Recovery & S3 Retention Pruning (`internal/queue`, `cmd/worker`)**:
  - Concurrency-safe `FOR UPDATE SKIP LOCKED` scheduling (`PGVAULT_SCHEDULER_INTERVAL`) and job claiming.
  - Worker lease expiry (`PGVAULT_JOB_LEASE_DURATION`) automatically recovers crashed/stuck jobs.
  - Per-target retention policies (`retention_keep_last` and `retention_max_age_days`) prune expired S3/R2 objects first and mark `pruned_at` in PostgreSQL.
- **Live Connection Tester, Streaming Download/Decrypt & Offline DR (`internal/api`, `cmd/pgvault-decrypt`)**:
  - `POST /api/v1/targets/test-connection` verifies PostgreSQL reachability and server version with a 5s timeout without ever leaking credentials.
  - `GET /api/v1/artifacts/{id}/download` and `/decrypt` stream encrypted `.pgv` or decrypted `.dump` files straight from S3/R2 without temp files.
  - `cmd/pgvault-decrypt` decrypts `.pgv` backups completely offline with zero server dependency.
- **High-Density Dark Observability Control Plane (`web/`)**: Linear/Vercel-inspired dark UI with slide-over target creation/editing, live Test Connection, execution inspector drawer (`lease_expires_at`, restore latency, copyable error logs), one-click `.pgv` / `.dump` downloads, and Telegram alert configuration.

---

## Architecture

```mermaid
flowchart LR
    UI["Next.js Control Plane (web)"] -->|REST + Bearer/X-API-Key| API["PGVault API (cmd/api)"]
    API -->|Targets / Jobs / Artifacts / Alerts| APPDB[("App PostgreSQL")]
    API -.->|Stream Download & Decrypt| S3[("S3 / Cloudflare R2")]
    WORKER["PGVault Worker (cmd/worker)"] -->|SKIP LOCKED Queue / Scheduler / Lease Recovery| APPDB
    TARGETDB[("Target PostgreSQL")] -->|pg_dump custom stdout| PIPE["io.Pipe -> AES-256-GCM -> io.Pipe"]
    PIPE -->|Multipart Upload| S3
    S3 -->|DownloadStream -> DecryptStream| VERIFIER["Ephemeral Docker PG (NetworkMode: none)"]
    WORKER -->|pg_restore + read-only sanity query| VERIFIER
    WORKER -->|Retention Auto-Prune| S3
    WORKER -->|Redacted Alerts| TG["Telegram Bot API"]
```

---

## Production / Cross-Host VPS Deployment

PGVault works across remote hosts (AWS RDS, Cloud SQL, Neon, self-hosted PostgreSQL over private/public IPs or domains with `sslmode=require|verify-ca|verify-full`, AWS S3, Cloudflare R2, and MinIO).

```bash
cp .env.example .env
# Generate fresh 32-byte keys:
openssl rand -hex 32   # -> PGVAULT_KEK_HEX
openssl rand -hex 32   # -> PGVAULT_API_KEY
stat -c '%g' /var/run/docker.sock   # -> DOCKER_GID

# Set PGVAULT_CORS_ORIGINS=https://pgvault.example.com
# Set NEXT_PUBLIC_API_URL=https://api.pgvault.example.com
docker compose -f docker-compose.prod.yml up -d --build
```

> **Security Note**: Store `PGVAULT_KEK_HEX` in an external secret manager or offline vault. Without the KEK, wrapped DEKs and encrypted backups cannot be decrypted. For public multi-user production deployments, leave `NEXT_PUBLIC_API_KEY` empty and supply the API key via the dashboard's **Connection** popover.

---

## Disaster Recovery (Offline Decryption Without Server)

If your PGVault control plane (`api`, `worker`, `app-db`) is completely unavailable, you can still recover any `.pgv` backup directly from S3/R2 using only:
1. The encrypted `.pgv` file downloaded from S3/R2.
2. Your 64-hex-character `PGVAULT_KEK_HEX`.
3. The artifact's KEK-encrypted `wrapped_dek` (copied from the Execution Inspector or queried from `backup_artifacts`: `SELECT id, object_key, encode(wrapped_dek, 'base64') FROM backup_artifacts;`).

Decrypt directly to a `.dump` file:

```bash
export PGVAULT_KEK_HEX="<your-64-hex-char-kek>"
go run ./cmd/pgvault-decrypt \
  --in backup.pgv \
  --wrapped-dek "<base64-or-hex-wrapped-dek>" \
  --out restored.dump

pg_restore --no-owner --no-privileges --dbname="postgres://user:pass@host:5432/mydb" restored.dump
```

Or stream straight into `pg_restore` with zero plaintext written to disk:

```bash
export PGVAULT_KEK_HEX="<your-64-hex-char-kek>"
go run ./cmd/pgvault-decrypt \
  --in backup.pgv \
  --wrapped-dek "<base64-or-hex-wrapped-dek>" \
  --out - | pg_restore --no-owner --no-privileges --dbname="postgres://user:pass@host:5432/mydb"
```

---

## Testing & Verification

```bash
# Unit tests (no Docker required)
go vet ./...
go test -v -race ./...

# Full integration tests (requires app-db, target-db, s3)
docker compose up -d app-db target-db s3
go test -v -race -tags=integration ./...

# Build all Go binaries
go build ./...

# Build Next.js dashboard
cd web && npm ci && npm run build
```

## License

MIT License — see [LICENSE](LICENSE).
