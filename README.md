# PGVault

Zero-knowledge, streaming PostgreSQL backup & automated restore verification platform written in Go with a Next.js control plane dashboard.

## Key Features

- **Zero-Disk Streaming Backups (`internal/pgdump`)**: Streams `pg_dump --format=custom --no-owner --no-privileges` directly through in-memory `io.Pipe` chains into AES-256-GCM encryption and S3 multipart upload—no plaintext dump files are ever written to disk.
- **Envelope Encryption & Chunked AEAD (`internal/crypto`)**:
  - Generates a fresh 32-byte random DEK per backup and wraps it with a 32-byte KEK via AES-256-GCM.
  - Streams 64 KiB chunks in `PGV1` format with header AAD authentication, per-chunk nonces (`noncePrefix || chunkIndex || finalFlag`), truncation detection (including 0-byte streams), chunk reordering protection, trailing-byte rejection, and on-the-fly ciphertext SHA-256 hashing.
- **S3 / Cloudflare R2 Compatible Storage (`internal/storage`)**: Multipart streaming uploads via `aws-sdk-go-v2` with automatic multipart abort (`LeavePartsOnError: false`) on context cancellation or stream failure.
- **Automated Ephemeral Docker Restore Verification (`internal/verifier`)**:
  - Spins up an isolated temporary `postgres:<major>-alpine` container with `NetworkMode: "none"` and strict CPU/Memory/PID limits.
  - Streams S3 ciphertext -> `DecryptStream` -> `pg_restore --exit-on-error`, verifies restored user table counts, and runs optional read-only sanity queries (`BEGIN TRANSACTION READ ONLY` + `SET LOCAL statement_timeout = '5s'`).
  - Always removes the container and its anonymous volumes in `defer` (`Force: true, RemoveVolumes: true`).
- **Concurrency-Safe PostgreSQL Job Queue (`internal/queue`)**: Uses `SELECT ... FOR UPDATE SKIP LOCKED` with retry exponential backoff and state transition validation.
- **Credential-Safe Telegram Alerting (`internal/notify`)**: Dispatches backup/verification success & failure notifications while redacting DB passwords, S3 secrets, KEK/DEK values, and Telegram bot tokens.
- **REST API & Next.js Dashboard (`internal/api`, `cmd/api`, `web/`)**: Manage targets, trigger backups, inspect jobs & verified artifacts, and configure Telegram alerts across localhost or remote VPS/domain hosts.

---

## Architecture

```mermaid
flowchart LR
    UI["Next.js Dashboard (web)"] -->|REST + Bearer/X-API-Key| API["PGVault API (cmd/api)"]
    API -->|Targets / Jobs / Alerts| APPDB[("App PostgreSQL")]
    WORKER["PGVault Worker (cmd/worker)"] -->|FOR UPDATE SKIP LOCKED| APPDB
    TARGETDB[("Target PostgreSQL")] -->|pg_dump custom stdout| PIPE1["io.Pipe"]
    PIPE1 -->|chunked AES-256-GCM| CRYPTO["internal/crypto"]
    CRYPTO -->|io.Pipe| S3[("S3 / Cloudflare R2")]
    WORKER -->|orchestrates| CRYPTO
    S3 -->|DownloadStream -> DecryptStream| VERIFIER["Ephemeral Docker PG (NetworkMode: none)"]
    WORKER -->|pg_restore + sanity query| VERIFIER
    WORKER -->|sanitized alerts| TG["Telegram Bot API"]
```

---

## Generating Keys (`KEK` & `API Key`)

Generate a fresh 32-byte (64-hex-char) Key Encryption Key and API key using OpenSSL:

```bash
# 32-byte Key Encryption Key (PGVAULT_KEK_HEX)
openssl rand -hex 32

# API authentication key (PGVAULT_API_KEY)
openssl rand -hex 32
```

> **Important**: Store `PGVAULT_KEK_HEX` securely (e.g. secret manager / encrypted vault). Losing the KEK prevents unwrapping stored DEKs and target credentials.

---

## Running Locally (Development)

### 1. Start Dev Infrastructure (`app-db`, `target-db`, LocalStack S3)

```bash
docker compose up -d
```

### 2. Run API & Worker

```bash
export PGVAULT_DB_DSN="postgres://pgvault:pgvault_dev_password@127.0.0.1:5432/pgvault?sslmode=disable"
export PGVAULT_KEK_HEX="$(openssl rand -hex 32)"
export PGVAULT_API_KEY="dev-secret-key"
export PGVAULT_CORS_ORIGINS="http://localhost:3000,http://127.0.0.1:3000"

# Terminal 1: API server (listens on :8080)
go run ./cmd/api

# Terminal 2: Worker engine
go run ./cmd/worker
```

### 3. Run Next.js Dashboard

```bash
cd web
npm install
npm run dev
```

Open `http://localhost:3000`, enter your API Base URL (`http://127.0.0.1:8080`) and API Key (`dev-secret-key`), and start adding targets.

---

## Production / Cross-Host VPS Deployment

PGVault supports non-localhost / cross-host deployments (remote RDS, Cloud SQL, Neon, self-hosted PostgreSQL over private/public IP or domain with `sslmode=require|verify-ca|verify-full`, AWS S3, Cloudflare R2, or MinIO).

### 1. Configure `.env`

```bash
cp .env.example .env
```

Edit `.env` and fill in strong production values:
- `POSTGRES_PASSWORD` & `PGVAULT_DB_DSN` (uses internal `app-db:5432` hostname)
- `PGVAULT_KEK_HEX` (`openssl rand -hex 32`)
- `PGVAULT_API_KEY` (`openssl rand -hex 32`)
- `PGVAULT_CORS_ORIGINS`: comma-separated dashboard origins, e.g. `https://pgvault.example.com`
- `NEXT_PUBLIC_API_URL`: public API URL reachable by the browser (e.g. `https://api.pgvault.example.com`, or leave empty if serving API + Web under the same reverse-proxy origin)
- `DOCKER_GID`: Docker socket group ID on the host (`stat -c '%g' /var/run/docker.sock`)

### 2. Build & Launch with Production Compose

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Services started:
- `app-db`: PostgreSQL 16 with persistent volume `pgvault_app_db_data` (internal network only, not exposed to the internet).
- `api`: Non-root minimal container serving the REST API on `${PGVAULT_API_PORT:-8080}`.
- `worker`: Non-root container with `postgresql17-client` (`pg_dump`/`pg_restore`) and `/var/run/docker.sock` mounted for isolated `NetworkMode: "none"` verification containers.
- `web`: Non-root Next.js production server on `${PGVAULT_WEB_PORT:-3000}`.

Place a TLS reverse proxy (Caddy, Nginx, or Traefik) in front of `api` and `web` for HTTPS in production.

---

## Testing

### Unit Tests (No External Services Required)

```bash
go vet ./...
go test -v -race ./...
```

### Integration Tests (Requires `docker compose up -d`)

```bash
docker compose up -d
go test -v -race -tags=integration ./...
```

### Frontend Type-Check & Production Build

```bash
cd web
npm ci
npm run build
```
