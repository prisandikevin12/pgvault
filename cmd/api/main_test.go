package main

import (
	"strings"
	"testing"
)

func TestLoadEnvConfig(t *testing.T) {
	validKEK := strings.Repeat("ab", 32)

	env := map[string]string{
		"PGVAULT_DB_DSN":  "postgres://pgvault:pw@localhost:5432/pgvault?sslmode=disable",
		"PGVAULT_KEK_HEX": validKEK,
		"PGVAULT_API_KEY": "my-api-key",
	}
	cfg, err := loadEnvConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("loadEnvConfig() valid unexpected error: %v", err)
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, defaultListenAddr)
	}
	if cfg.APIKey != "my-api-key" {
		t.Errorf("APIKey = %q, want my-api-key", cfg.APIKey)
	}

	// Missing DSN -> error
	if _, err := loadEnvConfig(func(k string) string {
		if k == "PGVAULT_KEK_HEX" {
			return validKEK
		}
		return ""
	}); err == nil {
		t.Errorf("loadEnvConfig() with missing DSN succeeded, want error")
	}

	// Invalid KEK -> error
	if _, err := loadEnvConfig(func(k string) string {
		if k == "PGVAULT_DB_DSN" {
			return "postgres://x"
		}
		return "short"
	}); err == nil {
		t.Errorf("loadEnvConfig() with invalid KEK succeeded, want error")
	}
}
