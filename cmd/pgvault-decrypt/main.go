package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/prisandikevin12/pgvault/internal/crypto"
)

type decryptOptions struct {
	KEKHex     string
	WrappedDEK string
	InputPath  string
	OutputPath string
}

func main() {
	var opts decryptOptions
	flag.StringVar(&opts.KEKHex, "kek-hex", os.Getenv("PGVAULT_KEK_HEX"), "64-char hex-encoded 32-byte KEK (or set PGVAULT_KEK_HEX)")
	flag.StringVar(&opts.WrappedDEK, "wrapped-dek", os.Getenv("PGVAULT_WRAPPED_DEK"), "KEK-wrapped DEK in hex or base64 (or set PGVAULT_WRAPPED_DEK)")
	flag.StringVar(&opts.InputPath, "in", "", "Input encrypted .pgv file path (or '-' for stdin)")
	flag.StringVar(&opts.OutputPath, "out", "-", "Output decrypted .dump file path (or '-' for stdout)")
	flag.Parse()

	if err := runDecrypt(opts); err != nil {
		fmt.Fprintf(os.Stderr, "pgvault-decrypt error: %v\n", err)
		os.Exit(1)
	}
}

func runDecrypt(opts decryptOptions) error {
	kek, err := hex.DecodeString(strings.TrimSpace(opts.KEKHex))
	if err != nil || len(kek) != crypto.KeySize {
		return fmt.Errorf("kek-hex must be a 64-character hex-encoded 32-byte key")
	}
	defer clear(kek)

	wrappedDEK, err := decodeWrappedDEK(opts.WrappedDEK)
	if err != nil {
		return err
	}

	dek, err := crypto.UnwrapDEK(kek, wrappedDEK)
	if err != nil {
		return fmt.Errorf("unwrap DEK: %w", err)
	}
	defer clear(dek)

	inPath := strings.TrimSpace(opts.InputPath)
	if inPath == "" {
		return errors.New("--in path is required (use '-' for stdin)")
	}
	outPath := strings.TrimSpace(opts.OutputPath)
	if outPath == "" {
		outPath = "-"
	}

	var reader io.Reader
	if inPath == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(inPath)
		if err != nil {
			return fmt.Errorf("open input %q: %w", inPath, err)
		}
		defer f.Close()
		reader = f
	}

	var (
		writer  io.Writer
		outFile *os.File
	)
	if outPath == "-" {
		writer = os.Stdout
	} else {
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("create output %q: %w", outPath, err)
		}
		outFile = f
		writer = f
	}

	if err := crypto.DecryptStream(reader, writer, dek); err != nil {
		if outFile != nil {
			_ = outFile.Close()
			_ = os.Remove(outPath)
		}
		return fmt.Errorf("decrypt stream: %w", err)
	}

	if outFile != nil {
		if err := outFile.Close(); err != nil {
			return fmt.Errorf("close output %q: %w", outPath, err)
		}
	}
	return nil
}

// decodeWrappedDEK accepts either hex-encoded or base64-encoded wrapped DEK bytes.
func decodeWrappedDEK(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("--wrapped-dek (hex or base64) is required")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) >= 12+crypto.KeySize+16 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) >= 12+crypto.KeySize+16 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) >= 12+crypto.KeySize+16 {
		return b, nil
	}
	return nil, errors.New("invalid --wrapped-dek: expected hex or base64 encoded AES-256-GCM wrapped DEK")
}
