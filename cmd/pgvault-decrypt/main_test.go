package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/prisandikevin12/pgvault/internal/crypto"
)

func TestOfflineDecrypt_RoundTripHexAndBase64(t *testing.T) {
	kek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK(kek) error: %v", err)
	}
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK(dek) error: %v", err)
	}
	wrappedDEK, err := crypto.WrapDEK(kek, dek)
	if err != nil {
		t.Fatalf("WrapDEK() error: %v", err)
	}

	plaintext := make([]byte, 150*1024+77) // multi-chunk payload (> 2 chunks)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatalf("rand error: %v", err)
	}

	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "backup.pgv")
	outHexPath := filepath.Join(tmpDir, "restored-hex.dump")
	outB64Path := filepath.Join(tmpDir, "restored-b64.dump")

	var encBuf bytes.Buffer
	if _, err := crypto.EncryptStream(bytes.NewReader(plaintext), &encBuf, dek, crypto.DefaultChunkSize); err != nil {
		t.Fatalf("EncryptStream() error: %v", err)
	}
	if err := os.WriteFile(encPath, encBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("write enc file: %v", err)
	}

	// 1. Decrypt with hex-encoded wrapped DEK
	if err := runDecrypt(decryptOptions{
		KEKHex:     hex.EncodeToString(kek),
		WrappedDEK: hex.EncodeToString(wrappedDEK),
		InputPath:  encPath,
		OutputPath: outHexPath,
	}); err != nil {
		t.Fatalf("runDecrypt(hex) error: %v", err)
	}
	gotHex, err := os.ReadFile(outHexPath)
	if err != nil {
		t.Fatalf("read restored-hex.dump: %v", err)
	}
	if !bytes.Equal(gotHex, plaintext) {
		t.Fatalf("restored-hex.dump mismatch")
	}

	// 2. Decrypt with base64-encoded wrapped DEK
	if err := runDecrypt(decryptOptions{
		KEKHex:     hex.EncodeToString(kek),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		InputPath:  encPath,
		OutputPath: outB64Path,
	}); err != nil {
		t.Fatalf("runDecrypt(base64) error: %v", err)
	}
	gotB64, err := os.ReadFile(outB64Path)
	if err != nil {
		t.Fatalf("read restored-b64.dump: %v", err)
	}
	if !bytes.Equal(gotB64, plaintext) {
		t.Fatalf("restored-b64.dump mismatch")
	}
}

func TestOfflineDecrypt_WrongKEKAndTamperedFile(t *testing.T) {
	kek, _ := crypto.GenerateDEK()
	wrongKEK, _ := crypto.GenerateDEK()
	dek, _ := crypto.GenerateDEK()
	wrappedDEK, _ := crypto.WrapDEK(kek, dek)

	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "backup.pgv")
	outPath := filepath.Join(tmpDir, "out.dump")

	var encBuf bytes.Buffer
	_, _ = crypto.EncryptStream(bytes.NewReader([]byte("secret-sql")), &encBuf, dek, 1024)
	_ = os.WriteFile(encPath, encBuf.Bytes(), 0o600)

	// Wrong KEK must fail
	if err := runDecrypt(decryptOptions{
		KEKHex:     hex.EncodeToString(wrongKEK),
		WrappedDEK: hex.EncodeToString(wrappedDEK),
		InputPath:  encPath,
		OutputPath: outPath,
	}); err == nil {
		t.Fatalf("runDecrypt(wrong KEK) succeeded, want error")
	}

	// Tampered ciphertext must fail and not leave partial output file
	tampered := append([]byte(nil), encBuf.Bytes()...)
	tampered[len(tampered)-1] ^= 0x01
	tamperedPath := filepath.Join(tmpDir, "tampered.pgv")
	_ = os.WriteFile(tamperedPath, tampered, 0o600)

	if err := runDecrypt(decryptOptions{
		KEKHex:     hex.EncodeToString(kek),
		WrappedDEK: hex.EncodeToString(wrappedDEK),
		InputPath:  tamperedPath,
		OutputPath: outPath,
	}); err == nil {
		t.Fatalf("runDecrypt(tampered) succeeded, want error")
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("expected output file to be cleaned up on decrypt failure")
	}
}
