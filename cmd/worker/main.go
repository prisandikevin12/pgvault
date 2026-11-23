package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/db"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := runMain(logger); err != nil {
		logger.Error("worker terminated with error", "error", err)
		os.Exit(1)
	}
}

func runMain(logger *slog.Logger) error {
	appDSN := os.Getenv("PGVAULT_DB_DSN")
	if appDSN == "" {
		return fmt.Errorf("PGVAULT_DB_DSN environment variable is required")
	}

	kekHex := os.Getenv("PGVAULT_KEK_HEX")
	kek, err := hex.DecodeString(kekHex)
	if err != nil || len(kek) != crypto.KeySize {
		return fmt.Errorf("PGVAULT_KEK_HEX must be a 64-character hex-encoded 32-byte key")
	}
	defer clear(kek)

	pollInterval := defaultPollInterval
	if v := os.Getenv("PGVAULT_POLL_INTERVAL"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid PGVAULT_POLL_INTERVAL: %w", err)
		}
		pollInterval = parsed
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.ConnectPool(ctx, appDSN)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		return err
	}

	worker, err := NewWorker(pool, WorkerConfig{
		WorkerID:     os.Getenv("PGVAULT_WORKER_ID"),
		PollInterval: pollInterval,
		KEK:          kek,
	}, nil, logger)
	if err != nil {
		return err
	}

	return worker.Run(ctx)
}
