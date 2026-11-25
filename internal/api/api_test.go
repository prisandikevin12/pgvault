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
