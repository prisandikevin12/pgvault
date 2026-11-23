package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	defaultTelegramBaseURL = "https://api.telegram.org"
	defaultHTTPTimeout     = 10 * time.Second
	maxSanitizedMessageLen = 1500
)

// EventType identifies the lifecycle event being reported to alert channels.
type EventType string

const (
	EventBackupSucceeded EventType = "backup_succeeded"
	EventBackupFailed    EventType = "backup_failed"
)

// Event contains sanitized metadata about a backup/verification outcome.
type Event struct {
	Type               EventType
	TargetName         string
	JobID              int64
	ObjectKey          string
	PlaintextBytes     int64
	CiphertextBytes    int64
	RestoreDurationMs  int64
	RestoredTables     int
	VerificationPassed bool
	ErrorMessage       string
	Timestamp          time.Time
}

// Notifier dispatches backup lifecycle notifications to an alerting channel.
type Notifier interface {
	Notify(ctx context.Context, event Event) error
}

var (
	urlCredsPattern      = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+):([^/\s@]+)@`)
	kvSecretPattern      = regexp.MustCompile(`(?i)\b(password|passwd|pwd|pgpassword|secret|secret_key|aws_secret_access_key|access_key|bot_token|token|kek|dek)\s*([=:])\s*([^\s&'",;]+)`)
	telegramBotPathRegex = regexp.MustCompile(`\bbot\d+:[A-Za-z0-9_-]{8,}\b`)
	telegramRawTokRegex  = regexp.MustCompile(`\b\d{5,}:[A-Za-z0-9_-]{16,}\b`)
)

// SanitizeMessage strips embedded URL passwords, key-value secrets, and Telegram bot tokens.
func SanitizeMessage(s string) string {
	cleaned := urlCredsPattern.ReplaceAllString(s, "${1}:***@")
	cleaned = kvSecretPattern.ReplaceAllString(cleaned, "${1}${2}[REDACTED]")
	cleaned = telegramBotPathRegex.ReplaceAllString(cleaned, "bot[REDACTED]")
	cleaned = telegramRawTokRegex.ReplaceAllString(cleaned, "[REDACTED_TOKEN]")
	if len(cleaned) > maxSanitizedMessageLen {
		cleaned = cleaned[:maxSanitizedMessageLen] + "...(truncated)"
	}
	return cleaned
}

// FormatEventMessage builds a human-readable, credential-free notification message.
func FormatEventMessage(event Event) string {
	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	var b strings.Builder
	switch event.Type {
	case EventBackupSucceeded:
		fmt.Fprintf(&b, "[PGVault] Backup & Verification SUCCEEDED\n")
	default:
		fmt.Fprintf(&b, "[PGVault] Backup/Verification FAILED\n")
	}

	fmt.Fprintf(&b, "Target: %s\n", SanitizeMessage(event.TargetName))
	fmt.Fprintf(&b, "Job: #%d\n", event.JobID)
	if event.ObjectKey != "" {
		fmt.Fprintf(&b, "Object: %s\n", SanitizeMessage(event.ObjectKey))
	}

	if event.Type == EventBackupSucceeded {
		fmt.Fprintf(&b, "Size: %d B plaintext / %d B ciphertext\n", event.PlaintextBytes, event.CiphertextBytes)
		fmt.Fprintf(&b, "Verified: %v (tables=%d, restore=%dms)\n", event.VerificationPassed, event.RestoredTables, event.RestoreDurationMs)
	} else if event.ErrorMessage != "" {
		fmt.Fprintf(&b, "Error: %s\n", SanitizeMessage(event.ErrorMessage))
	}

	fmt.Fprintf(&b, "Time: %s", ts.UTC().Format(time.RFC3339))
	return b.String()
}

// TelegramOption customizes TelegramNotifier behavior.
type TelegramOption func(*TelegramNotifier)

// WithBaseURL overrides the Telegram Bot API base URL (useful for testing).
func WithBaseURL(baseURL string) TelegramOption {
	return func(t *TelegramNotifier) {
		if strings.TrimSpace(baseURL) != "" {
			t.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

// WithHTTPClient overrides the HTTP client used by TelegramNotifier.
func WithHTTPClient(c *http.Client) TelegramOption {
	return func(t *TelegramNotifier) {
		if c != nil {
			t.httpClient = c
		}
	}
}

// TelegramNotifier sends backup alerts via the Telegram Bot API sendMessage endpoint.
type TelegramNotifier struct {
	botToken   string
	chatID     string
	baseURL    string
	httpClient *http.Client
}

// NewTelegramNotifier validates credentials and constructs a TelegramNotifier with timeout protection.
func NewTelegramNotifier(botToken, chatID string, opts ...TelegramOption) (*TelegramNotifier, error) {
	if strings.TrimSpace(botToken) == "" {
		return nil, errors.New("notify: telegram bot token is required")
	}
	if strings.TrimSpace(chatID) == "" {
		return nil, errors.New("notify: telegram chat ID is required")
	}

	t := &TelegramNotifier{
		botToken:   strings.TrimSpace(botToken),
		chatID:     strings.TrimSpace(chatID),
		baseURL:    defaultTelegramBaseURL,
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
	}
	for _, opt := range opts {
		opt(t)
	}
	return t, nil
}

type telegramSendPayload struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

type telegramAPIResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

// Notify sends the formatted, sanitized event message to the configured Telegram chat.
func (t *TelegramNotifier) Notify(ctx context.Context, event Event) error {
	payload := telegramSendPayload{
		ChatID:                t.chatID,
		Text:                  FormatEventMessage(event),
		DisableWebPagePreview: true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: marshal telegram payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", t.baseURL, t.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: create telegram request: %s", t.scrubToken(err.Error()))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("notify: send telegram request: %s", t.scrubToken(err.Error()))
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var apiResp telegramAPIResponse
	_ = json.Unmarshal(respBody, &apiResp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !apiResp.OK {
		desc := strings.TrimSpace(apiResp.Description)
		if desc == "" {
			desc = strings.TrimSpace(string(respBody))
		}
		return fmt.Errorf("notify: telegram API error (status %d): %s", resp.StatusCode, t.scrubToken(desc))
	}
	return nil
}

func (t *TelegramNotifier) scrubToken(s string) string {
	return SanitizeMessage(strings.ReplaceAll(s, t.botToken, "[REDACTED]"))
}
