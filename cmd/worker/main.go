package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/db"
)

type workerEnvConfig struct {
	DBDSN             string
	WorkerID          string
	PollInterval      time.Duration
	SchedulerInterval time.Duration
	PruneInterval     time.Duration
	JobLeaseDuration  time.Duration
	KEK               []byte
}

func loadWorkerEnvConfig(getenv func(string) string) (workerEnvConfig, error) {
	appDSN := strings.TrimSpace(getenv("PGVAULT_DB_DSN"))
	if appDSN == "" {
		return workerEnvConfig{}, fmt.Errorf("PGVAULT_DB_DSN environment variable is required")
	}

	kekHex := strings.TrimSpace(getenv("PGVAULT_KEK_HEX"))
	kek, err := hex.DecodeString(kekHex)
	if err != nil || len(kek) != crypto.KeySize {
		return workerEnvConfig{}, fmt.Errorf("PGVAULT_KEK_HEX must be a 64-character hex-encoded 32-byte key")
	}

	pollInterval, err := parsePositiveDurationEnv(getenv, "PGVAULT_POLL_INTERVAL", defaultPollInterval)
	if err != nil {
		return workerEnvConfig{}, err
	}
	schedulerInterval, err := parsePositiveDurationEnv(getenv, "PGVAULT_SCHEDULER_INTERVAL", defaultSchedulerInterval)
	if err != nil {
		return workerEnvConfig{}, err
	}
	pruneInterval, err := parsePositiveDurationEnv(getenv, "PGVAULT_PRUNE_INTERVAL", schedulerInterval)
	if err != nil {
		return workerEnvConfig{}, err
	}
	leaseDuration, err := parsePositiveDurationEnv(getenv, "PGVAULT_JOB_LEASE_DURATION", defaultJobLeaseDuration)
	if err != nil {
		return workerEnvConfig{}, err
	}

	return workerEnvConfig{
		DBDSN:             appDSN,
		WorkerID:          strings.TrimSpace(getenv("PGVAULT_WORKER_ID")),
		PollInterval:      pollInterval,
		SchedulerInterval: schedulerInterval,
		PruneInterval:     pruneInterval,
		JobLeaseDuration:  leaseDuration,
		KEK:               kek,
	}, nil
}

func parsePositiveDurationEnv(getenv func(string) string, key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid %s %q: must be a positive duration", key, raw)
	}
	return d, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := runMain(logger); err != nil {
		logger.Error("worker terminated with error", "error", err)
		os.Exit(1)
	}
}

func runMain(logger *slog.Logger) error {
	cfg, err := loadWorkerEnvConfig(os.Getenv)
	if err != nil {
		return err
	}
	defer clear(cfg.KEK)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.ConnectPool(ctx, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		return err
	}

	worker, err := NewWorker(pool, WorkerConfig{
		WorkerID:          cfg.WorkerID,
		PollInterval:      cfg.PollInterval,
		SchedulerInterval: cfg.SchedulerInterval,
		PruneInterval:     cfg.PruneInterval,
		JobLeaseDuration:  cfg.JobLeaseDuration,
		KEK:               cfg.KEK,
	}, nil, logger)
	if err != nil {
		return err
	}

	return worker.Run(ctx)
}
