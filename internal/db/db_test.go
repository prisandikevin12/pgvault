package db

import (
	"strings"
	"testing"

	"github.com/prisandikevin12/pgvault/internal/crypto"
)

func TestProtectUnprotectSecret(t *testing.T) {
	kek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error: %v", err)
	}
	wrongKEK, _ := crypto.GenerateDEK()

	secret := "postgres://target_admin:super_secret_pw@127.0.0.1:5433/customer_app?sslmode=disable"
	enc1, err := ProtectSecret(kek, secret)
	if err != nil {
		t.Fatalf("ProtectSecret() error: %v", err)
	}
	if !strings.HasPrefix(enc1, "enc:v1:") {
		t.Fatalf("expected enc:v1: prefix, got %q", enc1)
	}
	if strings.Contains(enc1, "super_secret_pw") {
		t.Fatalf("protected secret contains plaintext password")
	}

	enc2, err := ProtectSecret(kek, secret)
	if err != nil {
		t.Fatalf("ProtectSecret() second call error: %v", err)
	}
	if enc1 == enc2 {
		t.Fatalf("ProtectSecret() produced identical ciphertexts; expected random nonce")
	}

	dec, err := UnprotectSecret(kek, enc1)
	if err != nil {
		t.Fatalf("UnprotectSecret() error: %v", err)
	}
	if dec != secret {
		t.Fatalf("UnprotectSecret() = %q, want %q", dec, secret)
	}

	if _, err := UnprotectSecret(wrongKEK, enc1); err == nil {
		t.Fatalf("UnprotectSecret() with wrong KEK succeeded, want error")
	}

	// Empty secret stays empty
	emptyEnc, err := ProtectSecret(kek, "")
	if err != nil || emptyEnc != "" {
		t.Fatalf("ProtectSecret(empty) = %q, %v; want empty, nil", emptyEnc, err)
	}

	// Plaintext fallback (unprefixed value) passes through unchanged
	plain, err := UnprotectSecret(kek, "plain-dev-value")
	if err != nil || plain != "plain-dev-value" {
		t.Fatalf("UnprotectSecret(plain) = %q, %v; want plain-dev-value, nil", plain, err)
	}

	// Invalid KEK length fails
	if _, err := ProtectSecret(make([]byte, 16), secret); err == nil {
		t.Errorf("ProtectSecret() with 16-byte KEK succeeded, want error")
	}
}
