package queue

import (
	"testing"
	"time"
)

func TestValidateTransition(t *testing.T) {
	valid := [][2]string{
		{StatusQueued, StatusRunning},
		{StatusRunning, StatusVerifying},
		{StatusRunning, StatusQueued},
		{StatusRunning, StatusFailed},
		{StatusVerifying, StatusSucceeded},
		{StatusVerifying, StatusQueued},
		{StatusVerifying, StatusFailed},
	}
	for _, pair := range valid {
		if err := ValidateTransition(pair[0], pair[1]); err != nil {
			t.Errorf("ValidateTransition(%q, %q) unexpected error: %v", pair[0], pair[1], err)
		}
	}

	invalid := [][2]string{
		{StatusQueued, StatusSucceeded},
		{StatusQueued, StatusVerifying},
		{StatusQueued, StatusFailed},
		{StatusRunning, StatusSucceeded},
		{StatusSucceeded, StatusQueued},
		{StatusSucceeded, StatusRunning},
		{StatusSucceeded, StatusFailed},
		{StatusFailed, StatusQueued},
		{StatusFailed, StatusRunning},
		{StatusFailed, StatusSucceeded},
		{"unknown", StatusRunning},
	}
	for _, pair := range invalid {
		if err := ValidateTransition(pair[0], pair[1]); err == nil {
			t.Errorf("ValidateTransition(%q, %q) succeeded, want error", pair[0], pair[1])
		}
	}
}

func TestComputeBackoff(t *testing.T) {
	base := 10 * time.Second
	max := 60 * time.Second

	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{0, 10 * time.Second},
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 40 * time.Second},
		{4, 60 * time.Second}, // capped at max
		{10, 60 * time.Second},
	}

	for _, tc := range cases {
		if got := ComputeBackoff(tc.attempts, base, max); got != tc.want {
			t.Errorf("ComputeBackoff(%d) = %v, want %v", tc.attempts, got, tc.want)
		}
	}
}

func TestDecideFailureDisposition(t *testing.T) {
	cases := []struct {
		name        string
		attempts    int
		maxAttempts int
		retryable   bool
		want        string
	}{
		{"retryable_under_limit", 1, 3, true, StatusQueued},
		{"retryable_at_limit", 3, 3, true, StatusFailed},
		{"retryable_over_limit", 4, 3, true, StatusFailed},
		{"non_retryable_under_limit", 1, 3, false, StatusFailed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideFailureDisposition(tc.attempts, tc.maxAttempts, tc.retryable); got != tc.want {
				t.Errorf("DecideFailureDisposition() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsTargetDue(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	tenMinAgo := now.Add(-10 * time.Minute)
	fiveMinAgo := now.Add(-5 * time.Minute)

	cases := []struct {
		name            string
		lastScheduledAt *time.Time
		intervalSeconds int
		want            bool
	}{
		{"never_scheduled_positive_interval", nil, 600, true},
		{"never_scheduled_zero_interval", nil, 0, false},
		{"never_scheduled_negative_interval", nil, -60, false},
		{"exact_interval_elapsed", &tenMinAgo, 600, true},
		{"past_interval_elapsed", &tenMinAgo, 300, true},
		{"not_due_yet", &fiveMinAgo, 600, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTargetDue(tc.lastScheduledAt, tc.intervalSeconds, now); got != tc.want {
				t.Errorf("IsTargetDue() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDecideStaleRecovery(t *testing.T) {
	status, msg := DecideStaleRecovery(1, 3)
	if status != StatusQueued {
		t.Errorf("DecideStaleRecovery(1, 3) status = %q, want %q", status, StatusQueued)
	}
	if msg != StaleJobRecoveredError {
		t.Errorf("DecideStaleRecovery(1, 3) msg = %q, want %q", msg, StaleJobRecoveredError)
	}

	status, msg = DecideStaleRecovery(3, 3)
	if status != StatusFailed {
		t.Errorf("DecideStaleRecovery(3, 3) status = %q, want %q", status, StatusFailed)
	}
	if msg != StaleJobMaxAttemptsError {
		t.Errorf("DecideStaleRecovery(3, 3) msg = %q, want %q", msg, StaleJobMaxAttemptsError)
	}
}

func TestComputeLeaseExpiry(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

	if got := ComputeLeaseExpiry(now, 0); !got.Equal(now.Add(DefaultJobLeaseDuration)) {
		t.Errorf("ComputeLeaseExpiry(default) = %v, want %v", got, now.Add(DefaultJobLeaseDuration))
	}
	if got := ComputeLeaseExpiry(now, 5*time.Minute); !got.Equal(now.Add(5 * time.Minute)) {
		t.Errorf("ComputeLeaseExpiry(5m) = %v, want %v", got, now.Add(5*time.Minute))
	}
}
