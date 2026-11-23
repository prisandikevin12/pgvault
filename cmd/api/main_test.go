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

func TestLoadEnvConfig_CORSOrigins(t *testing.T) {
	validKEK := strings.Repeat("cd", 32)
	baseEnv := map[string]string{
		"PGVAULT_DB_DSN":  "postgres://pgvault:pw@db.internal:5432/pgvault?sslmode=require",
		"PGVAULT_KEK_HEX": validKEK,
	}

	t.Run("default_when_empty", func(t *testing.T) {
		cfg, err := loadEnvConfig(func(k string) string { return baseEnv[k] })
		if err != nil {
			t.Fatalf("loadEnvConfig() error: %v", err)
		}
		if len(cfg.AllowedOrigins) != 2 || cfg.AllowedOrigins[0] != "http://localhost:3000" || cfg.AllowedOrigins[1] != "http://127.0.0.1:3000" {
			t.Fatalf("AllowedOrigins = %v, want default localhost origins", cfg.AllowedOrigins)
		}
	})

	t.Run("single_non_localhost_origin", func(t *testing.T) {
		cfg, err := loadEnvConfig(func(k string) string {
			if k == "PGVAULT_CORS_ORIGINS" {
				return " https://pgvault.example.com/ "
			}
			return baseEnv[k]
		})
		if err != nil {
			t.Fatalf("loadEnvConfig() error: %v", err)
		}
		if len(cfg.AllowedOrigins) != 1 || cfg.AllowedOrigins[0] != "https://pgvault.example.com" {
			t.Fatalf("AllowedOrigins = %v, want [https://pgvault.example.com]", cfg.AllowedOrigins)
		}
	})

	t.Run("multiple_origins_trimmed", func(t *testing.T) {
		cfg, err := loadEnvConfig(func(k string) string {
			if k == "PGVAULT_CORS_ORIGINS" {
				return "https://app.example.com , http://10.0.1.50:3000/ , https://203.0.113.10"
			}
			return baseEnv[k]
		})
		if err != nil {
			t.Fatalf("loadEnvConfig() error: %v", err)
		}
		want := []string{"https://app.example.com", "http://10.0.1.50:3000", "https://203.0.113.10"}
		if len(cfg.AllowedOrigins) != len(want) {
			t.Fatalf("AllowedOrigins = %v, want %v", cfg.AllowedOrigins, want)
		}
		for i := range want {
			if cfg.AllowedOrigins[i] != want[i] {
				t.Errorf("AllowedOrigins[%d] = %q, want %q", i, cfg.AllowedOrigins[i], want[i])
			}
		}
	})
}
