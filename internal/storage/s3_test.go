package storage

import (
	"bytes"
	"context"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid_minimal",
			cfg: Config{
				Region: "us-east-1",
				Bucket: "pgvault-backups",
			},
			wantErr: false,
		},
		{
			name: "valid_localstack_full",
			cfg: Config{
				EndpointURL:     "http://127.0.0.1:4566",
				Region:          "us-east-1",
				Bucket:          "pgvault-backups",
				AccessKeyID:     "test",
				SecretAccessKey: "test",
				ForcePathStyle:  true,
			},
			wantErr: false,
		},
		{
			name: "missing_bucket",
			cfg: Config{
				Region: "us-east-1",
			},
			wantErr: true,
		},
		{
			name: "missing_region",
			cfg: Config{
				Bucket: "pgvault-backups",
			},
			wantErr: true,
		},
		{
			name: "access_key_without_secret",
			cfg: Config{
				Region:      "us-east-1",
				Bucket:      "pgvault-backups",
				AccessKeyID: "only-key",
			},
			wantErr: true,
		},
		{
			name: "secret_without_access_key",
			cfg: Config{
				Region:          "us-east-1",
				Bucket:          "pgvault-backups",
				SecretAccessKey: "only-secret",
			},
			wantErr: true,
		},
		{
			name: "invalid_endpoint_scheme",
			cfg: Config{
				EndpointURL: "ftp://127.0.0.1:4566",
				Region:      "us-east-1",
				Bucket:      "pgvault-backups",
			},
			wantErr: true,
		},
		{
			name: "invalid_endpoint_no_host",
			cfg: Config{
				EndpointURL: "http://",
				Region:      "us-east-1",
				Bucket:      "pgvault-backups",
			},
			wantErr: true,
		},
		{
			name: "part_size_too_small",
			cfg: Config{
				Region:   "us-east-1",
				Bucket:   "pgvault-backups",
				PartSize: 1024,
			},
			wantErr: true,
		},
		{
			name: "negative_concurrency",
			cfg: Config{
				Region:      "us-east-1",
				Bucket:      "pgvault-backups",
				Concurrency: -1,
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Config.Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewClient_ValidationError(t *testing.T) {
	_, err := NewClient(context.Background(), Config{})
	if err == nil {
		t.Fatalf("NewClient() with empty config succeeded, want error")
	}
}

func TestClient_MethodInputValidation(t *testing.T) {
	client, err := NewClient(context.Background(), Config{
		EndpointURL:     "http://127.0.0.1:4566",
		Region:          "us-east-1",
		Bucket:          "pgvault-unit-test",
		AccessKeyID:     "test",
		SecretAccessKey: "test",
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	ctx := context.Background()

	if _, err := client.UploadStream(ctx, "", bytes.NewReader([]byte("x")), "application/octet-stream"); err == nil {
		t.Errorf("UploadStream() with empty key succeeded, want error")
	}
	if _, err := client.UploadStream(ctx, "k", nil, "application/octet-stream"); err == nil {
		t.Errorf("UploadStream() with nil reader succeeded, want error")
	}
	if _, err := client.DownloadStream(ctx, ""); err == nil {
		t.Errorf("DownloadStream() with empty key succeeded, want error")
	}
	if err := client.DeleteObject(ctx, ""); err == nil {
		t.Errorf("DeleteObject() with empty key succeeded, want error")
	}
}
