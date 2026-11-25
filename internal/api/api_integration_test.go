//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/db"
	"github.com/prisandikevin12/pgvault/internal/pgdump"
	"github.com/prisandikevin12/pgvault/internal/queue"
)

func testAppDBDSN() string {
	if dsn := os.Getenv("PGVAULT_TEST_APP_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://pgvault:pgvault_dev_password@127.0.0.1:5432/pgvault?sslmode=disable"
}

func TestAPI_Integration_FullLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.ConnectPool(ctx, testAppDBDSN())
	if err != nil {
		t.Fatalf("ConnectPool() error: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() error: %v", err)
	}

	kek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error: %v", err)
	}
	const apiKey = "integration-api-key-999"

	srv, err := NewServer(pool, Config{
		KEK:    kek,
		APIKey: apiKey,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path string, payload any, auth bool) (*http.Response, []byte) {
		t.Helper()
		var body *bytes.Reader
		if payload != nil {
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			body = bytes.NewReader(b)
		} else {
			body = bytes.NewReader(nil)
		}
		req, err := http.NewRequestWithContext(ctx, method, ts.URL+path, body)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if auth {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request %s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp, buf.Bytes()
	}

	// 1. GET /healthz (no auth required)
	resp, _ := doReq(http.MethodGet, "/healthz", nil, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want 200", resp.StatusCode)
	}

	// 2. POST /api/v1/targets -> encrypts secrets, never leaks plaintext
	const (
		secretDSN = "postgres://admin:SuperSecretDBPass_XYZ@127.0.0.1:5433/customer_app?sslmode=disable"
		secretS3  = "SuperSecretS3Key_XYZ"
	)
	targetName := fmt.Sprintf("api-int-target-%d", time.Now().UnixNano())

	resp, raw := doReq(http.MethodPost, "/api/v1/targets", CreateTargetRequest{
		Name:                  targetName,
		TargetDSN:             secretDSN,
		StorageEndpoint:       "http://127.0.0.1:4566",
		StorageRegion:         "us-east-1",
		StorageBucket:         "pgvault-api-int",
		StorageAccessKey:      "test",
		StorageSecretKey:      secretS3,
		StorageForcePathStyle: true,
		SanityQuery:           "SELECT 1",
		IntervalSeconds:       3600,
		RetentionKeepLast:     5,
		RetentionMaxAgeDays:   30,
	}, true)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/v1/targets status = %d, want 201 (body=%s)", resp.StatusCode, string(raw))
	}
	if strings.Contains(string(raw), "SuperSecretDBPass_XYZ") || strings.Contains(string(raw), secretS3) {
		t.Fatalf("SECURITY VIOLATION: POST /api/v1/targets leaked plaintext secret: %s", string(raw))
	}

	var createdTarget TargetResponse
	if err := json.Unmarshal(raw, &createdTarget); err != nil {
		t.Fatalf("unmarshal createdTarget: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, "DELETE FROM backup_targets WHERE id = $1", createdTarget.ID)
	})

	// Verify secrets stored encrypted in app-db
	dbTarget, err := db.GetTarget(ctx, pool, createdTarget.ID)
	if err != nil {
		t.Fatalf("db.GetTarget() error: %v", err)
	}
	if !strings.HasPrefix(dbTarget.TargetDSN, "enc:v1:") || !strings.HasPrefix(dbTarget.StorageSecretKey, "enc:v1:") {
		t.Fatalf("expected target secrets to be stored encrypted with enc:v1: prefix")
	}

	// 3. GET /api/v1/targets & GET /api/v1/targets/{id}
	resp, raw = doReq(http.MethodGet, "/api/v1/targets", nil, true)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), targetName) {
		t.Fatalf("GET /api/v1/targets failed: status=%d body=%s", resp.StatusCode, string(raw))
	}
	if strings.Contains(string(raw), "SuperSecretDBPass_XYZ") {
		t.Fatalf("GET /api/v1/targets leaked plaintext secret")
	}

	resp, raw = doReq(http.MethodGet, fmt.Sprintf("/api/v1/targets/%d", createdTarget.ID), nil, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/targets/{id} status = %d, want 200", resp.StatusCode)
	}

	// 4. PATCH /api/v1/targets/{id}
	newInterval := 7200
	newQuery := "SELECT count(*) FROM public.orders"
	newKeepLast := 3
	newMaxAge := 14
	resp, raw = doReq(http.MethodPatch, fmt.Sprintf("/api/v1/targets/%d", createdTarget.ID), UpdateTargetRequest{
		IntervalSeconds:     &newInterval,
		SanityQuery:         &newQuery,
		RetentionKeepLast:   &newKeepLast,
		RetentionMaxAgeDays: &newMaxAge,
	}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /api/v1/targets/{id} status = %d, want 200 (body=%s)", resp.StatusCode, string(raw))
	}
	var patchedTarget TargetResponse
	_ = json.Unmarshal(raw, &patchedTarget)
	if patchedTarget.IntervalSeconds != 7200 || patchedTarget.SanityQuery != newQuery ||
		patchedTarget.RetentionKeepLast != 3 || patchedTarget.RetentionMaxAgeDays != 14 {
		t.Fatalf("PATCH result mismatch: %+v", patchedTarget)
	}

	// Negative retention value on PATCH must return 400 Bad Request
	neg := -2
	resp, _ = doReq(http.MethodPatch, fmt.Sprintf("/api/v1/targets/%d", createdTarget.ID), UpdateTargetRequest{
		RetentionKeepLast: &neg,
	}, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PATCH with negative retention_keep_last status = %d, want 400", resp.StatusCode)
	}

	// 5. POST /api/v1/targets/{id}/backups -> 202 Accepted
	resp, raw = doReq(http.MethodPost, fmt.Sprintf("/api/v1/targets/%d/backups", createdTarget.ID), nil, true)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/v1/targets/{id}/backups status = %d, want 202 (body=%s)", resp.StatusCode, string(raw))
	}
	var triggeredJob JobResponse
	if err := json.Unmarshal(raw, &triggeredJob); err != nil {
		t.Fatalf("unmarshal triggeredJob: %v", err)
	}
	if triggeredJob.Status != queue.StatusQueued || triggeredJob.TargetID != createdTarget.ID {
		t.Fatalf("unexpected triggeredJob: %+v", triggeredJob)
	}

	// Attach a verified artifact for this job and inspect GET /api/v1/jobs/{id} & GET /api/v1/artifacts
	_, err = db.CreateArtifact(ctx, pool, db.BackupArtifact{
		JobID:              triggeredJob.ID,
		TargetID:           createdTarget.ID,
		ObjectKey:          "backups/api-int/test.pgv1",
		WrappedDEK:         []byte("wrapped-dek-bytes"),
		PlaintextBytes:     12345,
		CiphertextBytes:    12500,
		CiphertextSHA256:   "abcdef123456",
		PGMajorVersion:     16,
		Tables:             []pgdump.TableSnapshot{{Schema: "public", Name: "orders", EstimatedRows: 42}},
		VerificationPassed: true,
		RestoreDurationMs:  88,
	})
	if err != nil {
		t.Fatalf("CreateArtifact() error: %v", err)
	}

	resp, raw = doReq(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%d", triggeredJob.ID), nil, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/jobs/{id} status = %d, want 200 (body=%s)", resp.StatusCode, string(raw))
	}
	var jobDetail JobResponse
	if err := json.Unmarshal(raw, &jobDetail); err != nil {
		t.Fatalf("unmarshal jobDetail: %v", err)
	}
	if jobDetail.Artifact == nil || !jobDetail.Artifact.VerificationPassed || jobDetail.Artifact.RestoreDurationMs != 88 {
		t.Fatalf("expected embedded verified artifact in GET /api/v1/jobs/{id}, got %+v", jobDetail.Artifact)
	}

	resp, raw = doReq(http.MethodGet, fmt.Sprintf("/api/v1/artifacts?target_id=%d", createdTarget.ID), nil, true)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "backups/api-int/test.pgv1") {
		t.Fatalf("GET /api/v1/artifacts failed: status=%d body=%s", resp.StatusCode, string(raw))
	}

	// 6. PUT /api/v1/alerts/telegram & GET /api/v1/alerts -> bot_token encrypted, never returned plaintext
	const secretBotToken = "555666:SuperSecretTelegramBotToken_ABC"
	resp, raw = doReq(http.MethodPut, "/api/v1/alerts/telegram", UpsertTelegramAlertRequest{
		TargetID:        &createdTarget.ID,
		BotToken:        secretBotToken,
		ChatID:          "-100999888777",
		NotifyOnFailure: true,
		NotifyOnSuccess: true,
		Enabled:         true,
	}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/v1/alerts/telegram status = %d, want 200 (body=%s)", resp.StatusCode, string(raw))
	}
	if strings.Contains(string(raw), secretBotToken) {
		t.Fatalf("SECURITY VIOLATION: PUT /api/v1/alerts/telegram leaked plaintext bot_token")
	}

	resp, raw = doReq(http.MethodGet, "/api/v1/alerts", nil, true)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "-100999888777") {
		t.Fatalf("GET /api/v1/alerts failed: status=%d body=%s", resp.StatusCode, string(raw))
	}
	if strings.Contains(string(raw), secretBotToken) {
		t.Fatalf("SECURITY VIOLATION: GET /api/v1/alerts leaked plaintext bot_token")
	}

	// 7. DELETE /api/v1/targets/{id} -> 204 No Content, then GET -> 404 Not Found
	resp, _ = doReq(http.MethodDelete, fmt.Sprintf("/api/v1/targets/%d", createdTarget.ID), nil, true)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/v1/targets/{id} status = %d, want 204", resp.StatusCode)
	}
	resp, _ = doReq(http.MethodGet, fmt.Sprintf("/api/v1/targets/%d", createdTarget.ID), nil, true)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET deleted target status = %d, want 404", resp.StatusCode)
	}
}
