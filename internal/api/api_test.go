package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prisandikevin12/pgvault/internal/crypto"
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
