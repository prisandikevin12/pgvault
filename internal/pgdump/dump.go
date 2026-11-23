package pgdump

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/storage"
	"golang.org/x/sync/errgroup"
)

const (
	stderrTailLimit   = 8 * 1024 // retain last 8 KiB of pg_dump stderr for diagnostics
	backupContentType = "application/octet-stream"
)

// ObjectUploader abstracts streaming object upload (satisfied by *storage.Client).
type ObjectUploader interface {
	UploadStream(ctx context.Context, key string, r io.Reader, contentType string) (storage.UploadResult, error)
}

// TableSnapshot captures a non-system user table and its estimated row count.
type TableSnapshot struct {
	Schema        string
	Name          string
	EstimatedRows int64
}

// BackupRequest holds inputs required to execute an encrypted streaming backup.
type BackupRequest struct {
	DSN       string
	Storage   ObjectUploader
	ObjectKey string
	KEK       []byte
	ChunkSize int // optional; 0 defaults to crypto.DefaultChunkSize (64 KiB)
}

// BackupResult summarizes a completed encrypted streaming backup.
type BackupResult struct {
	ObjectKey        string
	WrappedDEK       []byte
	PlaintextBytes   int64
	CiphertextBytes  int64
	CiphertextSHA256 string
	Tables           []TableSnapshot
	Duration         time.Duration
}

// ValidateBackupRequest validates all fields of a BackupRequest.
func ValidateBackupRequest(req BackupRequest) error {
	if strings.TrimSpace(req.DSN) == "" {
		return errors.New("pgdump: DSN is required")
	}
	if req.Storage == nil {
		return errors.New("pgdump: storage uploader is required")
	}
	if strings.TrimSpace(req.ObjectKey) == "" {
		return errors.New("pgdump: object key is required")
	}
	if len(req.KEK) != crypto.KeySize {
		return fmt.Errorf("pgdump: KEK must be %d bytes, got %d", crypto.KeySize, len(req.KEK))
	}
	if req.ChunkSize < 0 || req.ChunkSize > crypto.MaxChunkSize {
		return fmt.Errorf("pgdump: invalid chunk size %d", req.ChunkSize)
	}
	return nil
}

// ParseMajorVersion extracts the PostgreSQL major version from server_version_num (e.g. "160004" -> 16).
func ParseMajorVersion(versionNum string) (int, error) {
	trimmed := strings.TrimSpace(versionNum)
	n, err := strconv.Atoi(trimmed)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("pgdump: invalid server_version_num %q", versionNum)
	}
	major := n / 10000
	if major <= 0 {
		return 0, fmt.Errorf("pgdump: invalid server_version_num %q", versionNum)
	}
	return major, nil
}

// DetectMajorVersion connects to PostgreSQL via pgx/v5 and returns its major version number.
func DetectMajorVersion(ctx context.Context, dsn string) (int, error) {
	if strings.TrimSpace(dsn) == "" {
		return 0, errors.New("pgdump: DSN is required")
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return 0, fmt.Errorf("pgdump: connect to detect version: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()

	var versionNum string
	if err := conn.QueryRow(ctx, "SHOW server_version_num;").Scan(&versionNum); err != nil {
		return 0, fmt.Errorf("pgdump: query server_version_num: %w", err)
	}
	return ParseMajorVersion(versionNum)
}

// CollectTableSnapshot returns non-system user tables along with their estimated row counts.
func CollectTableSnapshot(ctx context.Context, dsn string) ([]TableSnapshot, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("pgdump: DSN is required")
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgdump: connect to collect table snapshot: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()

	const query = `
		SELECT
			t.table_schema,
			t.table_name,
			COALESCE(s.n_live_tup, 0)::bigint AS estimated_rows
		FROM information_schema.tables t
		LEFT JOIN pg_stat_user_tables s
			ON s.schemaname = t.table_schema
		   AND s.relname = t.table_name
		WHERE t.table_type = 'BASE TABLE'
		  AND t.table_schema NOT IN ('pg_catalog', 'information_schema')
		  AND t.table_schema NOT LIKE 'pg_toast%'
		  AND t.table_schema NOT LIKE 'pg_temp_%'
		ORDER BY t.table_schema, t.table_name
	`

	rows, err := conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("pgdump: query user tables: %w", err)
	}
	defer rows.Close()

	var tables []TableSnapshot
	for rows.Next() {
		var snap TableSnapshot
		if err := rows.Scan(&snap.Schema, &snap.Name, &snap.EstimatedRows); err != nil {
			return nil, fmt.Errorf("pgdump: scan table snapshot: %w", err)
		}
		tables = append(tables, snap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgdump: iterate table snapshot: %w", err)
	}
	return tables, nil
}

// RunEncryptedBackup executes pg_dump in custom format and streams its output directly through
// AES-256-GCM chunked encryption into S3 multipart upload without writing plaintext to disk.
func RunEncryptedBackup(ctx context.Context, req BackupRequest) (*BackupResult, error) {
	if err := ValidateBackupRequest(req); err != nil {
		return nil, err
	}

	start := time.Now()

	tables, err := CollectTableSnapshot(ctx, req.DSN)
	if err != nil {
		return nil, err
	}

	dek, err := crypto.GenerateDEK()
	if err != nil {
		return nil, fmt.Errorf("pgdump: generate DEK: %w", err)
	}
	defer clear(dek)

	wrappedDEK, err := crypto.WrapDEK(req.KEK, dek)
	if err != nil {
		return nil, fmt.Errorf("pgdump: wrap DEK: %w", err)
	}

	stats, err := streamDumpEncryptUpload(
		ctx,
		req.Storage,
		req.ObjectKey,
		dek,
		req.ChunkSize,
		func(cmdCtx context.Context, stdout io.Writer) error {
			return runPGDump(cmdCtx, req.DSN, stdout)
		},
	)
	if err != nil {
		return nil, err
	}

	return &BackupResult{
		ObjectKey:        req.ObjectKey,
		WrappedDEK:       wrappedDEK,
		PlaintextBytes:   stats.PlaintextBytes,
		CiphertextBytes:  stats.CiphertextBytes,
		CiphertextSHA256: stats.CiphertextSHA256,
		Tables:           tables,
		Duration:         time.Since(start),
	}, nil
}

func runPGDump(ctx context.Context, dsn string, stdout io.Writer) error {
	stderrBuf := newTailBuffer(stderrTailLimit)
	cmd := exec.CommandContext(
		ctx,
		"pg_dump",
		"--format=custom",
		"--no-owner",
		"--no-privileges",
		"--dbname="+dsn,
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderrBuf

	if err := cmd.Run(); err != nil {
		stderrMsg := strings.TrimSpace(stderrBuf.String())
		if stderrMsg != "" {
			return fmt.Errorf("pgdump: pg_dump failed: %w: %s", err, stderrMsg)
		}
		return fmt.Errorf("pgdump: pg_dump failed: %w", err)
	}
	return nil
}

// streamDumpEncryptUpload coordinates the 3-stage streaming pipeline:
// dumpFn -> dumpPipe -> crypto.EncryptStream -> encPipe -> uploader.UploadStream.
// Any failure in one stage closes adjacent pipes with error and cancels the shared context
// so no goroutine leaks, no deadlocks occur, and incomplete uploads are aborted.
func streamDumpEncryptUpload(
	ctx context.Context,
	uploader ObjectUploader,
	objectKey string,
	dek []byte,
	chunkSize int,
	dumpFn func(ctx context.Context, w io.Writer) error,
) (crypto.StreamStats, error) {
	dumpR, dumpW := io.Pipe()
	encR, encW := io.Pipe()

	g, gctx := errgroup.WithContext(ctx)

	var stats crypto.StreamStats

	// Stage 1: Produce plaintext dump into dumpW.
	// dumpW is only closed cleanly (EOF) if dumpFn exits with nil error.
	g.Go(func() error {
		err := dumpFn(gctx, dumpW)
		if err != nil {
			_ = dumpW.CloseWithError(err)
			return err
		}
		return dumpW.Close()
	})

	// Stage 2: Read plaintext from dumpR, encrypt chunk-by-chunk into encW.
	// encW is only closed cleanly (EOF) if EncryptStream completes with nil error.
	g.Go(func() error {
		s, err := crypto.EncryptStream(dumpR, encW, dek, chunkSize)
		if err != nil {
			_ = dumpR.CloseWithError(err)
			_ = encW.CloseWithError(err)
			return err
		}
		stats = s
		_ = dumpR.Close()
		return encW.Close()
	})

	// Stage 3: Stream ciphertext from encR directly to S3 multipart uploader.
	g.Go(func() error {
		_, err := uploader.UploadStream(gctx, objectKey, encR, backupContentType)
		if err != nil {
			_ = encR.CloseWithError(err)
			return err
		}
		return encR.Close()
	})

	if err := g.Wait(); err != nil {
		return crypto.StreamStats{}, err
	}
	return stats, nil
}

// tailBuffer is a bounded writer that retains only the last `limit` bytes written.
type tailBuffer struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func newTailBuffer(limit int) *tailBuffer {
	if limit <= 0 {
		limit = stderrTailLimit
	}
	return &tailBuffer{limit: limit}
}

func (tb *tailBuffer) Write(p []byte) (int, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if len(p) >= tb.limit {
		tb.buf = append(tb.buf[:0], p[len(p)-tb.limit:]...)
		return len(p), nil
	}

	overflow := len(tb.buf) + len(p) - tb.limit
	if overflow > 0 {
		copy(tb.buf, tb.buf[overflow:])
		tb.buf = tb.buf[:len(tb.buf)-overflow]
	}
	tb.buf = append(tb.buf, p...)
	return len(p), nil
}

func (tb *tailBuffer) String() string {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return string(tb.buf)
}
