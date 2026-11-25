package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/db"
)

func newTestServer(t *testing.T, apiKey string) *Server {
	t.Helper()
	kek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error: %v", err)
	}
	srv, err := NewServer(nil, Config{
		KEK:    kek,
		APIKey: apiKey,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	return srv
}

func TestHealthz_NoAuthRequired(t *testing.T) {
	srv := newTestServer(t, "top-secret-key")

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal /healthz body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("GET /healthz body = %v, want status=ok", body)
	}
}

func TestAuthMiddleware(t *testing.T) {
	const apiKey = "pgvault-api-secret-123"
	srv := newTestServer(t, apiKey)

	// Missing auth -> 401
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth status = %d, want 401", rec.Code)
	}

	// Wrong Bearer token -> 401
	req = httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer status = %d, want 401", rec.Code)
	}

	// Wrong X-API-Key -> 401
	req = httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong X-API-Key status = %d, want 401", rec.Code)
	}

	// Valid Bearer token passes auth (hits validation 400 on invalid JSON body, NOT 401)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/targets", strings.NewReader("{bad-json"))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("valid bearer + bad json status = %d, want 400", rec.Code)
	}

	// Valid X-API-Key passes auth
	req = httptest.NewRequest(http.MethodPost, "/api/v1/targets", strings.NewReader("{bad-json"))
	req.Header.Set("X-API-Key", apiKey)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("valid X-API-Key + bad json status = %d, want 400", rec.Code)
	}
}

func TestCORSMiddleware(t *testing.T) {
	srv := newTestServer(t, "secret-key")

	for _, origin := range []string{"http://localhost:3000", "http://127.0.0.1:3000"} {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/targets", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("OPTIONS preflight for %s status = %d, want 204", origin, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("Allow-Origin = %q, want %q", got, origin)
		}
		methods := rec.Header().Get("Access-Control-Allow-Methods")
		for _, m := range []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"} {
			if !strings.Contains(methods, m) {
				t.Errorf("Allow-Methods %q missing %s", methods, m)
			}
		}
		headers := rec.Header().Get("Access-Control-Allow-Headers")
		for _, h := range []string{"Authorization", "X-API-Key", "Content-Type"} {
			if !strings.Contains(headers, h) {
				t.Errorf("Allow-Headers %q missing %s", headers, h)
			}
		}
	}

	// Disallowed origin must not be reflected
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin reflected in Allow-Origin: %q", got)
	}
}

func TestParseCORSOrigins(t *testing.T) {
	defaults := ParseCORSOrigins("")
	if len(defaults) != 2 || defaults[0] != "http://localhost:3000" || defaults[1] != "http://127.0.0.1:3000" {
		t.Fatalf("ParseCORSOrigins(\"\") = %v, want default localhost origins", defaults)
	}

	single := ParseCORSOrigins("  https://pgvault.example.com/ ")
	if len(single) != 1 || single[0] != "https://pgvault.example.com" {
		t.Fatalf("ParseCORSOrigins(single) = %v, want [https://pgvault.example.com]", single)
	}

	multi := ParseCORSOrigins(" https://pgvault.example.com/ , http://10.0.1.50:3000 , , https://203.0.113.10:8443 ")
	want := []string{"https://pgvault.example.com", "http://10.0.1.50:3000", "https://203.0.113.10:8443"}
	if len(multi) != len(want) {
		t.Fatalf("ParseCORSOrigins(multi) = %v, want %v", multi, want)
	}
	for i := range want {
		if multi[i] != want[i] {
			t.Errorf("multi[%d] = %q, want %q", i, multi[i], want[i])
		}
	}
}

func TestCORSMiddleware_CustomCrossHostOrigins(t *testing.T) {
	kek, _ := crypto.GenerateDEK()

	t.Run("single_origin", func(t *testing.T) {
		srv, err := NewServer(nil, Config{
			KEK:            kek,
			APIKey:         "key",
			AllowedOrigins: ParseCORSOrigins("https://backup.company.com/"),
		})
		if err != nil {
			t.Fatalf("NewServer() error: %v", err)
		}

		req := httptest.NewRequest(http.MethodOptions, "/api/v1/targets", nil)
		req.Header.Set("Origin", "https://backup.company.com")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://backup.company.com" {
			t.Errorf("Allow-Origin = %q, want https://backup.company.com", got)
		}
		if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
			t.Errorf("Vary = %q, want to contain Origin", got)
		}

		// Localhost is not allowed when explicitly overridden
		req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req2.Header.Set("Origin", "http://localhost:3000")
		rec2 := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec2, req2)
		if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("unexpected Allow-Origin for non-configured localhost: %q", got)
		}
	})

	t.Run("multi_origin", func(t *testing.T) {
		srv, err := NewServer(nil, Config{
			KEK:            kek,
			AllowedOrigins: ParseCORSOrigins("https://pgvault.company.com, http://10.0.1.25:3000"),
		})
		if err != nil {
			t.Fatalf("NewServer() error: %v", err)
		}

		for _, origin := range []string{"https://pgvault.company.com", "http://10.0.1.25:3000"} {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
				t.Errorf("Allow-Origin = %q, want %q", got, origin)
			}
			if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
				t.Errorf("Vary = %q, want Origin", got)
			}
		}

		// Disallowed origin
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set("Origin", "https://attacker.example.org")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("disallowed origin reflected: %q", got)
		}
	})
}

func TestValidateCreateTargetInput_CrossHostAndSSLModes(t *testing.T) {
	cases := []struct {
		name            string
		dsn             string
		storageEndpoint string
		wantErr         bool
	}{
		{
			name:            "domain_sslmode_require_cloudflare_r2",
			dsn:             "postgres://backup_user:secret@db.prod.company.com:5432/appdb?sslmode=require",
			storageEndpoint: "https://0123456789abcdef.r2.cloudflarestorage.com",
			wantErr:         false,
		},
		{
			name:            "private_ip_sslmode_disable_minio",
			dsn:             "postgres://pguser:pass@10.24.0.15:5432/billing?sslmode=disable",
			storageEndpoint: "http://10.24.0.20:9000",
			wantErr:         false,
		},
		{
			name:            "public_ip_sslmode_verify_ca_aws_s3",
			dsn:             "postgresql://pguser:pass@203.0.113.42:5432/analytics?sslmode=verify-ca&sslrootcert=/etc/ssl/certs/ca.pem",
			storageEndpoint: "",
			wantErr:         false,
		},
		{
			name:            "domain_sslmode_verify_full",
			dsn:             "postgresql://pguser:pass@rds.eu-west-1.amazonaws.com:5432/core?sslmode=verify-full",
			storageEndpoint: "https://s3.eu-west-1.amazonaws.com",
			wantErr:         false,
		},
		{
			name:            "keyword_value_dsn_verify_full",
			dsn:             "host=pg.internal.lan port=5432 user=pgvault password=secret dbname=orders sslmode=verify-full",
			storageEndpoint: "https://s3.example.com",
			wantErr:         false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := CreateTargetRequest{
				Name:            tc.name,
				TargetDSN:       tc.dsn,
				StorageEndpoint: tc.storageEndpoint,
				StorageRegion:   "auto",
				StorageBucket:   "prod-pg-backups",
				IntervalSeconds: 3600,
			}
			err := req.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("CreateTargetRequest.Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateCreateTargetInput(t *testing.T) {
	cases := []struct {
		name    string
		in      CreateTargetRequest
		wantErr bool
	}{
		{
			name: "valid",
			in: CreateTargetRequest{
				Name:            "prod-db",
				TargetDSN:       "postgres://u:p@localhost:5432/db",
				StorageEndpoint: "http://127.0.0.1:4566",
				StorageRegion:   "us-east-1",
				StorageBucket:   "backups",
				SanityQuery:     "SELECT count(*) FROM public.users",
				IntervalSeconds: 3600,
			},
			wantErr: false,
		},
		{
			name: "missing_name",
			in: CreateTargetRequest{
				TargetDSN:     "postgres://u:p@localhost:5432/db",
				StorageRegion: "us-east-1",
				StorageBucket: "backups",
			},
			wantErr: true,
		},
		{
			name: "missing_dsn",
			in: CreateTargetRequest{
				Name:          "prod-db",
				StorageRegion: "us-east-1",
				StorageBucket: "backups",
			},
			wantErr: true,
		},
		{
			name: "mutating_sanity_query",
			in: CreateTargetRequest{
				Name:          "prod-db",
				TargetDSN:     "postgres://u:p@localhost:5432/db",
				StorageRegion: "us-east-1",
				StorageBucket: "backups",
				SanityQuery:   "DROP TABLE users",
			},
			wantErr: true,
		},
		{
			name: "negative_interval",
			in: CreateTargetRequest{
				Name:            "prod-db",
				TargetDSN:       "postgres://u:p@localhost:5432/db",
				StorageRegion:   "us-east-1",
				StorageBucket:   "backups",
				IntervalSeconds: -10,
			},
			wantErr: true,
		},
		{
			name: "negative_retention_keep_last",
			in: CreateTargetRequest{
				Name:              "prod-db",
				TargetDSN:         "postgres://u:p@localhost:5432/db",
				StorageRegion:     "us-east-1",
				StorageBucket:     "backups",
				RetentionKeepLast: -1,
			},
			wantErr: true,
		},
		{
			name: "negative_retention_max_age_days",
			in: CreateTargetRequest{
				Name:                "prod-db",
				TargetDSN:           "postgres://u:p@localhost:5432/db",
				StorageRegion:       "us-east-1",
				StorageBucket:       "backups",
				RetentionMaxAgeDays: -5,
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("CreateTargetRequest.Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestHandleTestConnection_Unit(t *testing.T) {
	kek, _ := crypto.GenerateDEK()
	const apiKey = "test-conn-key"

	t.Run("success", func(t *testing.T) {
		srv, err := NewServer(nil, Config{
			KEK:    kek,
			APIKey: apiKey,
			PingTargetFn: func(_ context.Context, _ string) (string, int64, error) {
				return "16.4 (Debian 16.4-1)", 12, nil
			},
		})
		if err != nil {
			t.Fatalf("NewServer() error: %v", err)
		}

		body := `{"dsn":"postgres://admin:SuperSecretPass!@db.example.com:5432/app?sslmode=require"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/targets/test-connection", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		var resp TestConnectionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if !resp.OK || resp.ServerVersion != "16.4 (Debian 16.4-1)" || resp.LatencyMs != 12 {
			t.Fatalf("unexpected response: %+v", resp)
		}
	})

	t.Run("missing_dsn_returns_400", func(t *testing.T) {
		srv, _ := NewServer(nil, Config{KEK: kek, APIKey: apiKey})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/targets/test-connection", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("invalid_dsn_returns_400_without_password_leak", func(t *testing.T) {
		srv, _ := NewServer(nil, Config{KEK: kek, APIKey: apiKey})
		body := `{"dsn":"postgres://admin:UltraSecretPW99@host:notaport/db"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/targets/test-connection", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "UltraSecretPW99") {
			t.Fatalf("SECURITY VIOLATION: 400 error leaked DSN password: %s", rec.Body.String())
		}
	})

	t.Run("connection_failure_returns_502_without_password_leak", func(t *testing.T) {
		srv, _ := NewServer(nil, Config{
			KEK:    kek,
			APIKey: apiKey,
			PingTargetFn: func(_ context.Context, dsn string) (string, int64, error) {
				return "", 0, errors.New("dial failed for " + dsn + " password=UltraSecretPW99")
			},
		})
		body := `{"dsn":"postgres://admin:UltraSecretPW99@db.example.com:5432/app?sslmode=require"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/targets/test-connection", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 (body=%s)", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "UltraSecretPW99") {
			t.Fatalf("SECURITY VIOLATION: 502 error leaked DSN password: %s", rec.Body.String())
		}
	})
}

type fakeStreamDownloader struct {
	data map[string][]byte
}

func (f *fakeStreamDownloader) DownloadStream(_ context.Context, key string) (io.ReadCloser, error) {
	b, ok := f.data[key]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func TestHandleArtifactDownloadAndDecrypt_Unit(t *testing.T) {
	kek, _ := crypto.GenerateDEK()
	dek, _ := crypto.GenerateDEK()
	wrappedDEK, _ := crypto.WrapDEK(kek, dek)

	plaintext := []byte("PGDMP_TEST_BACKUP_CONTENT_FOR_STREAMING_DECRYPT_12345")
	var cipherBuf bytes.Buffer
	if _, err := crypto.EncryptStream(bytes.NewReader(plaintext), &cipherBuf, dek, 1024); err != nil {
		t.Fatalf("EncryptStream() error: %v", err)
	}
	ciphertext := cipherBuf.Bytes()

	prunedNow := time.Now().UTC()
	artifacts := map[int64]*db.BackupArtifact{
		1: {
			ID:         1,
			JobID:      10,
			TargetID:   100,
			ObjectKey:  "backups/valid.pgv1",
			WrappedDEK: wrappedDEK,
		},
		2: {
			ID:         2,
			JobID:      11,
			TargetID:   100,
			ObjectKey:  "backups/pruned.pgv1",
			WrappedDEK: wrappedDEK,
			PrunedAt:   &prunedNow,
		},
		3: {
			ID:         3,
			JobID:      12,
			TargetID:   100,
			ObjectKey:  "backups/corrupt.pgv1",
			WrappedDEK: wrappedDEK,
		},
	}

	corrupt := append([]byte(nil), ciphertext...)
	corrupt[len(corrupt)-1] ^= 0xFF

	downloader := &fakeStreamDownloader{
		data: map[string][]byte{
			"backups/valid.pgv1":   ciphertext,
			"backups/corrupt.pgv1": corrupt,
		},
	}

	const apiKey = "dl-key"
	srv, err := NewServer(nil, Config{
		KEK:    kek,
		APIKey: apiKey,
		ArtifactLookupFn: func(_ context.Context, id int64) (*db.BackupArtifact, *db.BackupTarget, error) {
			art, ok := artifacts[id]
			if !ok {
				return nil, nil, ErrArtifactNotFound
			}
			return art, &db.BackupTarget{ID: 100, Name: "prod"}, nil
		},
		StreamDownloaderFn: func(_ context.Context, _ db.BackupTarget) (StreamDownloader, error) {
			return downloader, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	t.Run("download_ciphertext", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/1/download", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		if !bytes.Equal(rec.Body.Bytes(), ciphertext) {
			t.Fatalf("downloaded ciphertext mismatch")
		}
		if !strings.Contains(rec.Header().Get("Content-Disposition"), ".pgv") {
			t.Errorf("Content-Disposition = %q, want .pgv filename", rec.Header().Get("Content-Disposition"))
		}
	})

	t.Run("decrypt_endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/1/decrypt", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		if !bytes.Equal(rec.Body.Bytes(), plaintext) {
			t.Fatalf("decrypted output mismatch: got %q, want %q", rec.Body.String(), string(plaintext))
		}
		if !strings.Contains(rec.Header().Get("Content-Disposition"), ".dump") {
			t.Errorf("Content-Disposition = %q, want .dump filename", rec.Header().Get("Content-Disposition"))
		}
	})

	t.Run("download_with_decrypted_query_param", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/1/download?decrypted=true", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), plaintext) {
			t.Fatalf("status=%d, body mismatch", rec.Code)
		}
	})

	t.Run("pruned_artifact_returns_410", func(t *testing.T) {
		for _, path := range []string{"/api/v1/artifacts/2/download", "/api/v1/artifacts/2/decrypt"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+apiKey)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusGone {
				t.Errorf("%s status = %d, want 410 Gone", path, rec.Code)
			}
		}
	})

	t.Run("not_found_returns_404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/999/download", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("corrupted_ciphertext_fails_decrypt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/3/decrypt", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatalf("expected non-200 status for corrupted ciphertext, got 200")
		}
	})
}
