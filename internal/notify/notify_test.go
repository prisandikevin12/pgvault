package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewTelegramNotifier_Validation(t *testing.T) {
	if _, err := NewTelegramNotifier("", "12345"); err == nil {
		t.Errorf("NewTelegramNotifier with empty token succeeded, want error")
	}
	if _, err := NewTelegramNotifier("123:abc", ""); err == nil {
		t.Errorf("NewTelegramNotifier with empty chatID succeeded, want error")
	}
	n, err := NewTelegramNotifier("123:abc", "987654")
	if err != nil {
		t.Fatalf("NewTelegramNotifier valid input unexpected error: %v", err)
	}
	if n == nil {
		t.Fatalf("expected non-nil TelegramNotifier")
	}
}

func TestTelegramNotifier_SuccessAndRedaction(t *testing.T) {
	var (
		gotPath    string
		gotPayload map[string]any
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodPost {
			t.Errorf("HTTP method = %s, want POST", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Errorf("decode payload error: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":42}}`))
	}))
	defer srv.Close()

	const botToken = "999999:SUPER_SECRET_BOT_TOKEN_XYZ"
	notifier, err := NewTelegramNotifier(botToken, "-100123456789", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("NewTelegramNotifier() error: %v", err)
	}

	event := Event{
		Type:         EventBackupFailed,
		TargetName:   "prod-billing",
		JobID:        77,
		ObjectKey:    "backups/prod-billing/2026.pgv1",
		ErrorMessage: "pg_dump failed for postgres://admin:TopSecretDBPass!@db.internal:5432/prod?password=AnotherSecret&aws_secret_access_key=AKIASECRET123456 bot999999:SUPER_SECRET_BOT_TOKEN_XYZ",
		Timestamp:    time.Now().UTC(),
	}

	if err := notifier.Notify(context.Background(), event); err != nil {
		t.Fatalf("Notify() unexpected error: %v", err)
	}

	if gotPath != "/bot"+botToken+"/sendMessage" {
		t.Errorf("request path = %q, want %q", gotPath, "/bot"+botToken+"/sendMessage")
	}
	if gotPayload["chat_id"] != "-100123456789" {
		t.Errorf("chat_id = %v, want -100123456789", gotPayload["chat_id"])
	}

	text, _ := gotPayload["text"].(string)
	if !strings.Contains(text, "prod-billing") || !strings.Contains(text, "#77") {
		t.Errorf("alert text missing target/job details: %q", text)
	}
	for _, secret := range []string{"TopSecretDBPass!", "AnotherSecret", "AKIASECRET123456", "SUPER_SECRET_BOT_TOKEN_XYZ"} {
		if strings.Contains(text, secret) {
			t.Errorf("SECURITY VIOLATION: alert text leaked secret %q: %q", secret, text)
		}
	}
}

func TestTelegramNotifier_APIErrorDoesNotLeakToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	defer srv.Close()

	const botToken = "111222:LEAK_CHECK_TOKEN_999"
	notifier, err := NewTelegramNotifier(botToken, "12345", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("NewTelegramNotifier() error: %v", err)
	}

	err = notifier.Notify(context.Background(), Event{
		Type:       EventBackupSucceeded,
		TargetName: "prod-db",
		JobID:      1,
	})
	if err == nil {
		t.Fatalf("Notify() on HTTP 401 succeeded, want error")
	}
	if strings.Contains(err.Error(), botToken) {
		t.Fatalf("SECURITY VIOLATION: error message leaked bot token: %v", err)
	}
}
