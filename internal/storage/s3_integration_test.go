//go:build integration

package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

func testS3Config(bucket string) Config {
	endpoint := os.Getenv("PGVAULT_TEST_S3_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4566"
	}
	region := os.Getenv("PGVAULT_TEST_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	accessKey := os.Getenv("PGVAULT_TEST_S3_ACCESS_KEY")
	if accessKey == "" {
		accessKey = "test"
	}
	secretKey := os.Getenv("PGVAULT_TEST_S3_SECRET_KEY")
	if secretKey == "" {
		secretKey = "test"
	}
	return Config{
		EndpointURL:     endpoint,
		Region:          region,
		Bucket:          bucket,
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		ForcePathStyle:  true,
	}
}

type failingReader struct {
	sent  int
	limit int
	err   error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.sent >= f.limit {
		return 0, f.err
	}
	n := len(p)
	if f.sent+n > f.limit {
		n = f.limit - f.sent
	}
	for i := 0; i < n; i++ {
		p[i] = 'a'
	}
	f.sent += n
	return n, nil
}

func TestS3Client_Integration_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bucket := fmt.Sprintf("pgvault-storage-test-%d", time.Now().UnixNano())
	client, err := NewClient(ctx, testS3Config(bucket))
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	// EnsureBucket must create bucket and be idempotent on repeated calls.
	if err := client.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket() first call error: %v", err)
	}
	if err := client.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket() second call error: %v", err)
	}

	// Stream a >5 MiB payload through io.Pipe so multipart upload is exercised.
	const payloadSize = 5*1024*1024 + 12345
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatalf("rand error: %v", err)
	}

	key := "integration/multipart-test.bin"
	pr, pw := io.Pipe()
	go func() {
		_, err := pw.Write(payload)
		_ = pw.CloseWithError(err)
	}()

	res, err := client.UploadStream(ctx, key, pr, "application/octet-stream")
	if err != nil {
		t.Fatalf("UploadStream() error: %v", err)
	}
	if res.Key != key {
		t.Errorf("UploadResult.Key = %q, want %q", res.Key, key)
	}
	if res.Bucket != bucket {
		t.Errorf("UploadResult.Bucket = %q, want %q", res.Bucket, bucket)
	}

	rc, err := client.DownloadStream(ctx, key)
	if err != nil {
		t.Fatalf("DownloadStream() error: %v", err)
	}
	got, err := io.ReadAll(rc)
	closeErr := rc.Close()
	if err != nil {
		t.Fatalf("reading DownloadStream() error: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("closing DownloadStream() error: %v", closeErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded payload mismatch: got %d bytes, want %d bytes", len(got), len(payload))
	}

	// DeleteObject and verify object is gone.
	if err := client.DeleteObject(ctx, key); err != nil {
		t.Fatalf("DeleteObject() error: %v", err)
	}
	if rc2, err := client.DownloadStream(ctx, key); err == nil {
		_ = rc2.Close()
		t.Fatalf("DownloadStream() after DeleteObject succeeded, want error")
	}
}

func TestS3Client_Integration_StreamErrorAndCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bucket := fmt.Sprintf("pgvault-storage-err-%d", time.Now().UnixNano())
	client, err := NewClient(ctx, testS3Config(bucket))
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if err := client.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket() error: %v", err)
	}

	// Stream reader returning error must fail upload and not leave an object.
	boom := errors.New("simulated stream read failure")
	badKey := "integration/should-not-exist.bin"
	if _, err := client.UploadStream(ctx, badKey, &failingReader{limit: 64 * 1024, err: boom}, "application/octet-stream"); err == nil {
		t.Fatalf("UploadStream() with failing reader succeeded, want error")
	}
	if rc, err := client.DownloadStream(ctx, badKey); err == nil {
		_ = rc.Close()
		t.Fatalf("object %q exists after failed UploadStream", badKey)
	}

	// Canceled context must fail upload cleanly.
	cancelCtx, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if _, err := client.UploadStream(cancelCtx, "integration/canceled.bin", bytes.NewReader([]byte("hello")), "application/octet-stream"); err == nil {
		t.Fatalf("UploadStream() with canceled context succeeded, want error")
	}
}
