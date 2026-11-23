package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prisandikevin12/pgvault/internal/api"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/db"
)

const defaultListenAddr = ":8080"

type apiEnvConfig struct {
	DBDSN          string
	KEK            []byte
	APIKey         string
	ListenAddr     string
	AllowedOrigins []string
}

func loadEnvConfig(getenv func(string) string) (apiEnvConfig, error) {
	dsn := strings.TrimSpace(getenv("PGVAULT_DB_DSN"))
	if dsn == "" {
		return apiEnvConfig{}, errors.New("PGVAULT_DB_DSN environment variable is required")
	}

	kekHex := strings.TrimSpace(getenv("PGVAULT_KEK_HEX"))
	kek, err := hex.DecodeString(kekHex)
	if err != nil || len(kek) != crypto.KeySize {
		return apiEnvConfig{}, errors.New("PGVAULT_KEK_HEX must be a 64-character hex-encoded 32-byte key")
	}

	addr := strings.TrimSpace(getenv("PGVAULT_API_ADDR"))
	if addr == "" {
		addr = defaultListenAddr
	}

	origins := api.ParseCORSOrigins(getenv("PGVAULT_CORS_ORIGINS"))

	return apiEnvConfig{
		DBDSN:          dsn,
		KEK:            kek,
		APIKey:         strings.TrimSpace(getenv("PGVAULT_API_KEY")),
		ListenAddr:     addr,
		AllowedOrigins: origins,
	}, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := runMain(logger); err != nil {
		logger.Error("api server exited with error", "error", err)
		os.Exit(1)
	}
}

func runMain(logger *slog.Logger) error {
	cfg, err := loadEnvConfig(os.Getenv)
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

	apiSrv, err := api.NewServer(pool, api.Config{
		KEK:            cfg.KEK,
		APIKey:         cfg.APIKey,
		AllowedOrigins: cfg.AllowedOrigins,
		Logger:         logger,
	})
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("pgvault api listening", "addr", cfg.ListenAddr, "auth_enabled", cfg.APIKey != "")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http listen: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutting down pgvault api gracefully")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	}
}
