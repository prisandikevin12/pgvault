package verifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/pgdump"
	"github.com/prisandikevin12/pgvault/internal/storage"
)

const (
	defaultPGMajorVersion = 16
	defaultTimeout        = 5 * time.Minute
	defaultMemoryBytes    = 512 * 1024 * 1024 // 512 MiB
	defaultNanoCPUs       = 1_000_000_000     // 1 vCPU
	defaultPidsLimit      = int64(256)
	logsTailLimit         = 4 * 1024 // 4 KiB max diagnostic log tail

	verifyDBName = "verify_db"
	verifyDBUser = "postgres"
	verifyDBPass = "pgvault_verify_ephemeral"
)

// VerifyRequest holds inputs required to verify an encrypted backup in an isolated Docker container.
type VerifyRequest struct {
	Storage        *storage.Client
	ObjectKey      string
	WrappedDEK     []byte
	KEK            []byte
	ExpectedTables []pgdump.TableSnapshot
	SanityQuery    string
	PGMajorVersion int
	Timeout        time.Duration
}

// VerifyResult contains the outcome and telemetry of an automated restore verification.
type VerifyResult struct {
	Passed            bool
	RestoreDurationMs int64
	PGVersionUsed     int
	ExpectedTables    int
	RestoredTables    int
	SanityQueryPassed bool
	LogsTail          string
	Error             string
	ContainerID       string
}

// ValidateVerifyRequest checks all required fields and sanity query safety rules.
func ValidateVerifyRequest(req VerifyRequest) error {
	if req.Storage == nil {
		return errors.New("verifier: storage client is required")
	}
	if strings.TrimSpace(req.ObjectKey) == "" {
		return errors.New("verifier: object key is required")
	}
	if len(req.WrappedDEK) == 0 {
		return errors.New("verifier: wrapped DEK is required")
	}
	if len(req.KEK) != crypto.KeySize {
		return fmt.Errorf("verifier: KEK must be %d bytes, got %d", crypto.KeySize, len(req.KEK))
	}
	if req.PGMajorVersion < 0 {
		return fmt.Errorf("verifier: invalid PostgreSQL major version %d", req.PGMajorVersion)
	}
	if req.Timeout < 0 {
		return fmt.Errorf("verifier: timeout must be non-negative, got %v", req.Timeout)
	}
	if err := ValidateSanityQuery(req.SanityQuery); err != nil {
		return err
	}
	return nil
}

var forbiddenSQLTokens = map[string]struct{}{
	"INSERT":              {},
	"UPDATE":              {},
	"DELETE":              {},
	"MERGE":               {},
	"DROP":                {},
	"ALTER":               {},
	"CREATE":              {},
	"TRUNCATE":            {},
	"GRANT":               {},
	"REVOKE":              {},
	"COPY":                {},
	"CALL":                {},
	"DO":                  {},
	"EXECUTE":             {},
	"PREPARE":             {},
	"DEALLOCATE":          {},
	"SET":                 {},
	"RESET":               {},
	"VACUUM":              {},
	"ANALYZE":             {},
	"CLUSTER":             {},
	"REINDEX":             {},
	"REFRESH":             {},
	"LOCK":                {},
	"LISTEN":              {},
	"NOTIFY":              {},
	"UNLISTEN":            {},
	"LOAD":                {},
	"CHECKPOINT":          {},
	"DISCARD":             {},
	"COMMENT":             {},
	"SECURITY":            {},
	"IMPORT":              {},
	"INTO":                {},
	"SET_CONFIG":          {},
	"PG_TERMINATE_BACKEND": {},
	"PG_CANCEL_BACKEND":   {},
	"PG_RELOAD_CONF":      {},
	"PG_ROTATE_LOGFILE":   {},
	"PG_READ_FILE":        {},
	"PG_READ_BINARY_FILE": {},
	"PG_LS_DIR":           {},
	"PG_STAT_FILE":        {},
	"LO_IMPORT":           {},
	"LO_EXPORT":           {},
	"LO_UNLINK":           {},
	"DBLINK":              {},
	"DBLINK_EXEC":         {},
}

// ValidateSanityQuery ensures an optional sanity query is strictly a single read-only SELECT/WITH query.
func ValidateSanityQuery(query string) error {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return nil
	}
	if strings.ContainsRune(trimmed, '\x00') {
		return errors.New("verifier: sanity query contains null byte")
	}
	if strings.HasPrefix(trimmed, `\`) {
		return errors.New("verifier: psql meta-commands are not allowed in sanity query")
	}

	cleaned, err := stripCommentsAndStringLiterals(trimmed)
	if err != nil {
		return err
	}

	cleaned = strings.TrimSpace(cleaned)
	// Allow at most one trailing semicolon; reject any embedded semicolons (multi-statement).
	cleaned = strings.TrimRight(cleaned, " \t\r\n")
	if strings.HasSuffix(cleaned, ";") {
		cleaned = strings.TrimSpace(cleaned[:len(cleaned)-1])
	}
	if strings.ContainsRune(cleaned, ';') {
		return errors.New("verifier: multiple SQL statements are not allowed in sanity query")
	}
	if strings.ContainsRune(cleaned, '\\') {
		return errors.New("verifier: backslash commands are not allowed in sanity query")
	}

	tokens := extractSQLTokens(cleaned)
	if len(tokens) == 0 {
		return errors.New("verifier: sanity query contains no executable SQL")
	}
	if tokens[0] != "SELECT" && tokens[0] != "WITH" {
		return fmt.Errorf("verifier: sanity query must start with SELECT or WITH, got %q", tokens[0])
	}

	for _, tok := range tokens {
		if _, banned := forbiddenSQLTokens[tok]; banned {
			return fmt.Errorf("verifier: forbidden SQL keyword/function %q in sanity query", tok)
		}
	}
	return nil
}

// stripCommentsAndStringLiterals replaces SQL comments and single-quoted string literals with spaces,
// while rejecting dollar-quoted blocks and unclosed comments/strings.
func stripCommentsAndStringLiterals(sql string) (string, error) {
	var b strings.Builder
	b.Grow(len(sql))

	n := len(sql)
	for i := 0; i < n; {
		ch := sql[i]

		// Line comment: -- ... \n
		if ch == '-' && i+1 < n && sql[i+1] == '-' {
			i += 2
			for i < n && sql[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
			continue
		}

		// Block comment: /* ... */ (supports nesting in PostgreSQL)
		if ch == '/' && i+1 < n && sql[i+1] == '*' {
			depth := 1
			i += 2
			for i < n && depth > 0 {
				if sql[i] == '/' && i+1 < n && sql[i+1] == '*' {
					depth++
					i += 2
				} else if sql[i] == '*' && i+1 < n && sql[i+1] == '/' {
					depth--
					i += 2
				} else {
					i++
				}
			}
			if depth != 0 {
				return "", errors.New("verifier: unclosed block comment in sanity query")
			}
			b.WriteByte(' ')
			continue
		}

		// Single-quoted string literal: '...' with '' escape
		if ch == '\'' {
			i++
			closed := false
			for i < n {
				if sql[i] == '\'' {
					if i+1 < n && sql[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return "", errors.New("verifier: unclosed string literal in sanity query")
			}
			b.WriteByte(' ')
			continue
		}

		// Reject PostgreSQL dollar-quoting ($$ or $tag$) in sanity queries
		if ch == '$' {
			return "", errors.New("verifier: dollar-quoted strings are not allowed in sanity query")
		}

		b.WriteByte(ch)
		i++
	}
	return b.String(), nil
}

func extractSQLTokens(s string) []string {
	var tokens []string
	var cur strings.Builder

	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, strings.ToUpper(cur.String()))
			cur.Reset()
		}
	}

	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return tokens
}

func sanitizeSanityQueryForExec(query string) string {
	trimmed := strings.TrimSpace(query)
	return strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
}

// minPGMajorForArchiveHeader returns the minimum PostgreSQL major version needed to restore
// a custom-format PGDMP archive header (e.g. archive 1.16 requires PG 17+/18).
func minPGMajorForArchiveHeader(header []byte) int {
	if len(header) < 7 || string(header[:5]) != "PGDMP" {
		return 0
	}
	vMaj := header[5]
	vMin := header[6]
	if vMaj == 1 {
		switch {
		case vMin >= 16:
			return 18
		case vMin == 15:
			return 16
		}
	}
	return 0
}

// RunVerification verifies an encrypted S3 backup by decrypting and restoring it into an
// ephemeral, network-isolated PostgreSQL Docker container, checking table counts and an
// optional read-only sanity query, and always removing the container and its volumes.
func RunVerification(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	result := &VerifyResult{
		ExpectedTables: len(req.ExpectedTables),
	}

	fail := func(err error) (*VerifyResult, error) {
		result.Passed = false
		result.Error = err.Error()
		return result, err
	}

	if err := ValidateVerifyRequest(req); err != nil {
		return fail(err)
	}

	dek, err := crypto.UnwrapDEK(req.KEK, req.WrappedDEK)
	if err != nil {
		return fail(fmt.Errorf("verifier: unwrap DEK: %w", err))
	}
	defer clear(dek)

	timeout := req.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pgVersion := req.PGMajorVersion
	if pgVersion == 0 {
		pgVersion = defaultPGMajorVersion
	}
	// If the dump was produced by a newer pg_dump (e.g. archive 1.16 on PG 18 host dumping PG 16),
	// automatically upgrade the verification container image so pg_restore supports the archive format.
	if minVer := probeArchiveMinPGVersion(runCtx, req.Storage, req.ObjectKey, dek); minVer > pgVersion {
		pgVersion = minVer
	}
	result.PGVersionUsed = pgVersion

	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fail(fmt.Errorf("verifier: init docker client: %w", err))
	}
	defer dockerCli.Close()

	imageRef := fmt.Sprintf("postgres:%d-alpine", pgVersion)
	if err := ensureImage(runCtx, dockerCli, imageRef); err != nil {
		return fail(fmt.Errorf("verifier: ensure image %s: %w", imageRef, err))
	}

	pidsLimit := defaultPidsLimit
	createResp, err := dockerCli.ContainerCreate(
		runCtx,
		&container.Config{
			Image: imageRef,
			Env: []string{
				"POSTGRES_USER=" + verifyDBUser,
				"POSTGRES_PASSWORD=" + verifyDBPass,
				"POSTGRES_DB=" + verifyDBName,
			},
			Labels: map[string]string{
				"pgvault.managed":  "true",
				"pgvault.verifier": "true",
			},
		},
		&container.HostConfig{
			NetworkMode: "none",
			Resources: container.Resources{
				NanoCPUs:  defaultNanoCPUs,
				Memory:    defaultMemoryBytes,
				PidsLimit: &pidsLimit,
			},
		},
		nil,
		nil,
		"",
	)
	if err != nil {
		return fail(fmt.Errorf("verifier: create container: %w", err))
	}

	containerID := createResp.ID
	result.ContainerID = containerID
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = dockerCli.ContainerRemove(cleanupCtx, containerID, container.RemoveOptions{
			Force:         true,
			RemoveVolumes: true,
		})
	}()

	if err := dockerCli.ContainerStart(runCtx, containerID, container.StartOptions{}); err != nil {
		return fail(fmt.Errorf("verifier: start container: %w", err))
	}

	logsBuf := newTailBuffer(logsTailLimit)
	appendLog := func(label, text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		_, _ = fmt.Fprintf(logsBuf, "[%s] %s\n", label, text)
		result.LogsTail = strings.TrimSpace(logsBuf.String())
	}

	if err := waitForPostgres(runCtx, dockerCli, containerID); err != nil {
		appendLog("postgres", fetchContainerLogsTail(dockerCli, containerID))
		return fail(fmt.Errorf("verifier: postgres readiness check failed: %w", err))
	}

	restoreDurationMs, restoreStderr, err := streamRestoreIntoContainer(runCtx, dockerCli, containerID, req.Storage, req.ObjectKey, dek)
	result.RestoreDurationMs = restoreDurationMs
	appendLog("pg_restore", restoreStderr)
	if err != nil {
		return fail(err)
	}

	restoredCount, countStderr, err := countRestoredUserTables(runCtx, dockerCli, containerID)
	appendLog("table_check", countStderr)
	if err != nil {
		return fail(fmt.Errorf("verifier: count restored tables: %w", err))
	}
	result.RestoredTables = restoredCount

	if len(req.ExpectedTables) > 0 && restoredCount != len(req.ExpectedTables) {
		return fail(fmt.Errorf("verifier: restored table count mismatch: got %d, want %d", restoredCount, len(req.ExpectedTables)))
	}

	if strings.TrimSpace(req.SanityQuery) != "" {
		sanityStderr, err := runSanityQuery(runCtx, dockerCli, containerID, req.SanityQuery)
		appendLog("sanity_query", sanityStderr)
		if err != nil {
			result.SanityQueryPassed = false
			return fail(fmt.Errorf("verifier: sanity query failed: %w", err))
		}
		result.SanityQueryPassed = true
	}

	result.Passed = true
	result.LogsTail = strings.TrimSpace(logsBuf.String())
	return result, nil
}

// probeArchiveMinPGVersion reads just the first 8 bytes of the decrypted dump to detect
// the PGDMP custom-archive format version. On any read/decrypt error it returns 0 so the
// main restore pipeline handles and reports the error cleanly.
func probeArchiveMinPGVersion(ctx context.Context, s3Client *storage.Client, key string, dek []byte) int {
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	body, err := s3Client.DownloadStream(probeCtx, key)
	if err != nil {
		return 0
	}

	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = crypto.DecryptStream(body, pw, dek)
		_ = pw.Close()
	}()

	var hdr [8]byte
	_, readErr := io.ReadFull(pr, hdr[:])
	_ = pr.Close()
	_ = body.Close()
	cancel()
	<-done

	if readErr != nil {
		return 0
	}
	return minPGMajorForArchiveHeader(hdr[:])
}

func ensureImage(ctx context.Context, dockerCli *client.Client, imageRef string) error {
	_, err := dockerCli.ImageInspect(ctx, imageRef)
	if err == nil {
		return nil
	}
	if !errdefs.IsNotFound(err) {
		return err
	}

	rc, err := dockerCli.ImagePull(ctx, imageRef, image.PullOptions{})
	if err != nil {
		return err
	}
	defer rc.Close()
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return err
	}
	return nil
}

func waitForPostgres(ctx context.Context, dockerCli *client.Client, containerID string) error {
	deadline := time.Now().Add(60 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		// Check TCP loopback readiness (ensures initdb temporary unix-socket phase has finished).
		exitCode, _, _, err := execSimple(ctx, dockerCli, containerID, []string{
			"pg_isready", "-h", "127.0.0.1", "-U", verifyDBUser, "-d", verifyDBName,
		}, false)
		if err == nil && exitCode == 0 {
			// Confirm SQL queries succeed on verify_db.
			sqlExit, _, _, sqlErr := execSimple(ctx, dockerCli, containerID, []string{
				"psql", "-h", "127.0.0.1", "-U", verifyDBUser, "-d", verifyDBName, "-X", "-q", "-c", "SELECT 1",
			}, false)
			if sqlErr == nil && sqlExit == 0 {
				return nil
			}
		}

		// Fail fast if container exited unexpectedly.
		if inspect, inspErr := dockerCli.ContainerInspect(ctx, containerID); inspErr == nil && inspect.State != nil && !inspect.State.Running {
			return fmt.Errorf("container exited early with code %d", inspect.State.ExitCode)
		}

		if time.Now().After(deadline) {
			return errors.New("timed out waiting for postgres to become ready")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func streamRestoreIntoContainer(
	ctx context.Context,
	dockerCli *client.Client,
	containerID string,
	s3Client *storage.Client,
	objectKey string,
	dek []byte,
) (int64, string, error) {
	s3Body, err := s3Client.DownloadStream(ctx, objectKey)
	if err != nil {
		return 0, "", fmt.Errorf("verifier: download backup %q: %w", objectKey, err)
	}
	defer s3Body.Close()

	execResp, err := dockerCli.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Cmd: []string{
			"pg_restore",
			"--exit-on-error",
			"--no-owner",
			"--no-privileges",
			"-h", "127.0.0.1",
			"-U", verifyDBUser,
			"-d", verifyDBName,
		},
		Env:          []string{"PGPASSWORD=" + verifyDBPass},
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	})
	if err != nil {
		return 0, "", fmt.Errorf("verifier: create pg_restore exec: %w", err)
	}

	hijacked, err := dockerCli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{Tty: false})
	if err != nil {
		return 0, "", fmt.Errorf("verifier: attach pg_restore exec: %w", err)
	}
	defer hijacked.Close()

	// Ensure context cancellation unblocks both S3 read and Docker hijacked I/O.
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = s3Body.Close()
			hijacked.Close()
		case <-stopWatch:
		}
	}()

	restoreStart := time.Now()
	stderrTail := newTailBuffer(logsTailLimit)

	var (
		wg      sync.WaitGroup
		decErr  error
		copyErr error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		decErr = crypto.DecryptStream(s3Body, hijacked.Conn, dek)
		if decErr != nil {
			// Abort stdin/conn immediately so pg_restore exits with error instead of seeing clean EOF.
			hijacked.Close()
			return
		}
		_ = hijacked.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		// Discard stdout to avoid ever logging sensitive table content; capture stderr tail only.
		_, copyErr = stdcopy.StdCopy(io.Discard, stderrTail, hijacked.Reader)
	}()

	wg.Wait()
	close(stopWatch)
	<-watchDone

	durationMs := time.Since(restoreStart).Milliseconds()
	stderrStr := strings.TrimSpace(stderrTail.String())

	// Prioritize authentic cryptographic/stream errors over downstream broken-pipe errors.
	if decErr != nil {
		if isCryptoError(decErr) {
			return durationMs, stderrStr, fmt.Errorf("verifier: decrypt backup stream: %w", decErr)
		}
		// If pg_restore exited early and closed stdin, prefer its diagnostic stderr if present.
		if stderrStr != "" {
			return durationMs, stderrStr, fmt.Errorf("verifier: pg_restore failed (%w): %s", decErr, stderrStr)
		}
		return durationMs, stderrStr, fmt.Errorf("verifier: decrypt/restore stream failed: %w", decErr)
	}

	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		return durationMs, stderrStr, fmt.Errorf("verifier: read pg_restore output: %w", copyErr)
	}

	exitCode, err := waitExecExitCode(ctx, dockerCli, execResp.ID)
	if err != nil {
		return durationMs, stderrStr, fmt.Errorf("verifier: inspect pg_restore exit: %w", err)
	}
	if exitCode != 0 {
		if stderrStr != "" {
			return durationMs, stderrStr, fmt.Errorf("verifier: pg_restore exited with code %d: %s", exitCode, stderrStr)
		}
		return durationMs, stderrStr, fmt.Errorf("verifier: pg_restore exited with code %d", exitCode)
	}

	return durationMs, stderrStr, nil
}

func isCryptoError(err error) bool {
	return errors.Is(err, crypto.ErrDecryptionFailed) ||
		errors.Is(err, crypto.ErrInvalidHeader) ||
		errors.Is(err, crypto.ErrTruncatedStream) ||
		errors.Is(err, crypto.ErrTrailingData) ||
		errors.Is(err, crypto.ErrInvalidKeySize)
}

func countRestoredUserTables(ctx context.Context, dockerCli *client.Client, containerID string) (int, string, error) {
	const countSQL = `SELECT count(*)::bigint FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema') AND table_schema NOT LIKE 'pg_toast%' AND table_schema NOT LIKE 'pg_temp_%';`

	exitCode, stdout, stderr, err := execSimple(ctx, dockerCli, containerID, []string{
		"psql",
		"-h", "127.0.0.1",
		"-U", verifyDBUser,
		"-d", verifyDBName,
		"-X", "-q", "-t", "-A",
		"-v", "ON_ERROR_STOP=1",
		"-c", countSQL,
	}, true)
	if err != nil {
		return 0, stderr, err
	}
	if exitCode != 0 {
		return 0, stderr, fmt.Errorf("psql table count exited with code %d: %s", exitCode, strings.TrimSpace(stderr))
	}

	count, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		return 0, stderr, fmt.Errorf("parse restored table count %q: %w", strings.TrimSpace(stdout), err)
	}
	return count, stderr, nil
}

func runSanityQuery(ctx context.Context, dockerCli *client.Client, containerID string, sanityQuery string) (string, error) {
	cleaned := sanitizeSanityQueryForExec(sanityQuery)
	wrappedSQL := fmt.Sprintf("BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '5s'; %s; COMMIT;", cleaned)

	// CaptureStdout=false so query result rows never enter memory or LogsTail.
	exitCode, _, stderr, err := execSimple(ctx, dockerCli, containerID, []string{
		"psql",
		"-h", "127.0.0.1",
		"-U", verifyDBUser,
		"-d", verifyDBName,
		"-X", "-q", "-t", "-A",
		"-v", "ON_ERROR_STOP=1",
		"-c", wrappedSQL,
	}, false)
	if err != nil {
		return stderr, err
	}
	if exitCode != 0 {
		return stderr, fmt.Errorf("sanity query exited with code %d: %s", exitCode, strings.TrimSpace(stderr))
	}
	return stderr, nil
}

func execSimple(ctx context.Context, dockerCli *client.Client, containerID string, cmd []string, captureStdout bool) (int, string, string, error) {
	execResp, err := dockerCli.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Cmd:          cmd,
		Env:          []string{"PGPASSWORD=" + verifyDBPass},
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	})
	if err != nil {
		return -1, "", "", err
	}

	hijacked, err := dockerCli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{Tty: false})
	if err != nil {
		return -1, "", "", err
	}
	defer hijacked.Close()

	var stdoutBuf bytes.Buffer
	var stdoutWriter io.Writer = io.Discard
	if captureStdout {
		stdoutWriter = &stdoutBuf
	}
	stderrTail := newTailBuffer(logsTailLimit)

	if _, err := stdcopy.StdCopy(stdoutWriter, stderrTail, hijacked.Reader); err != nil && !errors.Is(err, io.EOF) {
		return -1, "", strings.TrimSpace(stderrTail.String()), err
	}

	exitCode, err := waitExecExitCode(ctx, dockerCli, execResp.ID)
	return exitCode, stdoutBuf.String(), strings.TrimSpace(stderrTail.String()), err
}

func waitExecExitCode(ctx context.Context, dockerCli *client.Client, execID string) (int, error) {
	for {
		inspect, err := dockerCli.ContainerExecInspect(ctx, execID)
		if err != nil {
			return -1, err
		}
		if !inspect.Running {
			return inspect.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func fetchContainerLogsTail(dockerCli *client.Client, containerID string) string {
	logCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rc, err := dockerCli.ContainerLogs(logCtx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       "40",
	})
	if err != nil {
		return ""
	}
	defer rc.Close()

	tail := newTailBuffer(logsTailLimit)
	_, _ = stdcopy.StdCopy(tail, tail, rc)
	return strings.TrimSpace(tail.String())
}

// tailBuffer retains only the last `limit` bytes written.
type tailBuffer struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func newTailBuffer(limit int) *tailBuffer {
	if limit <= 0 {
		limit = logsTailLimit
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
