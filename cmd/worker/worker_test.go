package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prisandikevin12/pgvault/internal/crypto"
)

func TestWorkerConfigValidate(t *testing.T) {
	kek, _ := crypto.GenerateDEK()

	if err := (WorkerConfig{KEK: kek}).Validate(); err != nil {
		t.Fatalf("valid WorkerConfig returned error: %v", err)
	}
	if err := (WorkerConfig{KEK: make([]byte, 16)}).Validate(); err == nil {
		t.Fatalf("WorkerConfig with 16-byte KEK succeeded, want error")
	}
	if err := (WorkerConfig{KEK: kek, SchedulerInterval: -time.Second}).Validate(); err == nil {
		t.Fatalf("WorkerConfig with negative SchedulerInterval succeeded, want error")
	}
	if err := (WorkerConfig{KEK: kek, JobLeaseDuration: -time.Second}).Validate(); err == nil {
		t.Fatalf("WorkerConfig with negative JobLeaseDuration succeeded, want error")
	}
	if err := (WorkerConfig{KEK: kek, PruneInterval: -time.Second}).Validate(); err == nil {
		t.Fatalf("WorkerConfig with negative PruneInterval succeeded, want error")
	}
}

func TestLoadWorkerEnvConfig(t *testing.T) {
	validKEK := strings.Repeat("ef", 32)
	base := map[string]string{
		"PGVAULT_DB_DSN":  "postgres://pgvault:pw@localhost:5432/pgvault?sslmode=disable",
		"PGVAULT_KEK_HEX": validKEK,
	}

	// Defaults
	cfg, err := loadWorkerEnvConfig(func(k string) string { return base[k] })
	if err != nil {
		t.Fatalf("loadWorkerEnvConfig(defaults) error: %v", err)
	}
	if cfg.SchedulerInterval != defaultSchedulerInterval {
		t.Errorf("SchedulerInterval = %v, want %v", cfg.SchedulerInterval, defaultSchedulerInterval)
	}
	if cfg.JobLeaseDuration != defaultJobLeaseDuration {
		t.Errorf("JobLeaseDuration = %v, want %v", cfg.JobLeaseDuration, defaultJobLeaseDuration)
	}
	if cfg.PruneInterval != defaultSchedulerInterval {
		t.Errorf("PruneInterval = %v, want %v", cfg.PruneInterval, defaultSchedulerInterval)
	}

	// Custom durations
	cfg, err = loadWorkerEnvConfig(func(k string) string {
		switch k {
		case "PGVAULT_SCHEDULER_INTERVAL":
			return "30s"
		case "PGVAULT_JOB_LEASE_DURATION":
			return "20m"
		case "PGVAULT_PRUNE_INTERVAL":
			return "2m"
		default:
			return base[k]
		}
	})
	if err != nil {
		t.Fatalf("loadWorkerEnvConfig(custom) error: %v", err)
	}
	if cfg.SchedulerInterval != 30*time.Second {
		t.Errorf("SchedulerInterval = %v, want 30s", cfg.SchedulerInterval)
	}
	if cfg.JobLeaseDuration != 20*time.Minute {
		t.Errorf("JobLeaseDuration = %v, want 20m", cfg.JobLeaseDuration)
	}
	if cfg.PruneInterval != 2*time.Minute {
		t.Errorf("PruneInterval = %v, want 2m", cfg.PruneInterval)
	}

	// Invalid duration rejected
	if _, err := loadWorkerEnvConfig(func(k string) string {
		if k == "PGVAULT_SCHEDULER_INTERVAL" {
			return "not-a-duration"
		}
		return base[k]
	}); err == nil {
		t.Errorf("loadWorkerEnvConfig with invalid PGVAULT_SCHEDULER_INTERVAL succeeded, want error")
	}
	if _, err := loadWorkerEnvConfig(func(k string) string {
		if k == "PGVAULT_JOB_LEASE_DURATION" {
			return "0s"
		}
		return base[k]
	}); err == nil {
		t.Errorf("loadWorkerEnvConfig with non-positive PGVAULT_JOB_LEASE_DURATION succeeded, want error")
	}
}

func TestSanitizeKeySegment(t *testing.T) {
	if got := sanitizeKeySegment("Prod Customer DB / v1"); got != "prod-customer-db-v1" {
		t.Errorf("sanitizeKeySegment() = %q, want %q", got, "prod-customer-db-v1")
	}
	if got := sanitizeKeySegment("   "); got != "target" {
		t.Errorf("sanitizeKeySegment(blank) = %q, want %q", got, "target")
	}
}
