package main

import (
	"testing"

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
}

func TestSanitizeKeySegment(t *testing.T) {
	if got := sanitizeKeySegment("Prod Customer DB / v1"); got != "prod-customer-db-v1" {
		t.Errorf("sanitizeKeySegment() = %q, want %q", got, "prod-customer-db-v1")
	}
	if got := sanitizeKeySegment("   "); got != "target" {
		t.Errorf("sanitizeKeySegment(blank) = %q, want %q", got, "target")
	}
}
