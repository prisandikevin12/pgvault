package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	// KeySize is the required length in bytes for AES-256 keys (KEK and DEK).
	KeySize = 32

	gcmNonceSize = 12
)

var (
	// ErrInvalidKeySize is returned when a KEK or DEK is not exactly 32 bytes.
	ErrInvalidKeySize = errors.New("crypto: key must be exactly 32 bytes")
	// ErrInvalidWrappedDEK is returned when the wrapped DEK payload is malformed or truncated.
	ErrInvalidWrappedDEK = errors.New("crypto: invalid wrapped DEK")
	// ErrDecryptionFailed is returned when AES-GCM authentication or decryption fails.
	ErrDecryptionFailed = errors.New("crypto: decryption failed")
)

// GenerateDEK generates a cryptographically secure random 32-byte Data Encryption Key.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("crypto: generate DEK: %w", err)
	}
	return dek, nil
}

// WrapDEK encrypts a 32-byte DEK using a 32-byte KEK with AES-256-GCM.
// The returned slice has a random 12-byte nonce prepended to the ciphertext and GCM tag.
func WrapDEK(kek, dek []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, fmt.Errorf("%w: got KEK length %d", ErrInvalidKeySize, len(kek))
	}
	if len(dek) != KeySize {
		return nil, fmt.Errorf("%w: got DEK length %d", ErrInvalidKeySize, len(dek))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("crypto: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: create GCM: %w", err)
	}

	out := make([]byte, gcmNonceSize, gcmNonceSize+KeySize+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, out[:gcmNonceSize]); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}

	return aead.Seal(out, out[:gcmNonceSize], dek, nil), nil
}

// UnwrapDEK decrypts a wrapped DEK using a 32-byte KEK with AES-256-GCM.
// It expects the 12-byte nonce prepended to the ciphertext and validates that
// the unwrapped DEK is exactly 32 bytes.
func UnwrapDEK(kek, wrapped []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, fmt.Errorf("%w: got KEK length %d", ErrInvalidKeySize, len(kek))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("crypto: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: create GCM: %w", err)
	}

	if len(wrapped) < gcmNonceSize+aead.Overhead() {
		return nil, ErrInvalidWrappedDEK
	}

	nonce := wrapped[:gcmNonceSize]
	ciphertext := wrapped[gcmNonceSize:]

	dek, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	if len(dek) != KeySize {
		return nil, fmt.Errorf("%w: unwrapped DEK length %d", ErrInvalidKeySize, len(dek))
	}

	return dek, nil
}
