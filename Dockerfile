# syntax=docker/dockerfile:1

FROM golang:1.27-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/pgvault-api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/pgvault-worker ./cmd/worker

# Minimal API runtime image (no pg_dump/docker CLI needed)
FROM alpine:3.21 AS api

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S pgvault && adduser -S -G pgvault pgvault

COPY --from=builder /out/pgvault-api /usr/local/bin/pgvault-api

USER pgvault
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/pgvault-api"]

# Worker runtime image with PostgreSQL client tools (pg_dump / pg_restore)
FROM alpine:3.21 AS worker

RUN apk add --no-cache ca-certificates tzdata postgresql17-client && \
    addgroup -S pgvault && adduser -S -G pgvault pgvault

COPY --from=builder /out/pgvault-worker /usr/local/bin/pgvault-worker

USER pgvault

ENTRYPOINT ["/usr/local/bin/pgvault-worker"]
