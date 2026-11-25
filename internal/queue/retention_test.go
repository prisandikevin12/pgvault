package queue

import (
	"testing"
	"time"
)

func TestSelectExpiredBackupJobs_DisabledPolicy(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	candidates := []RetentionCandidate{
		{ArtifactID: 1, JobID: 1, JobStatus: StatusSucceeded, ObjectKey: "k1", CreatedAt: now.Add(-48 * time.Hour)},
		{ArtifactID: 2, JobID: 2, JobStatus: StatusSucceeded, ObjectKey: "k2", CreatedAt: now.Add(-24 * time.Hour)},
	}

	expired := SelectExpiredBackupJobs(candidates, RetentionPolicy{KeepLast: 0, MaxAgeDays: 0}, now)
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired backups when policy is disabled, got %d", len(expired))
	}
}

func TestSelectExpiredBackupJobs_KeepLast(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// Unsorted input to verify newest-first sorting
	candidates := []RetentionCandidate{
		{ArtifactID: 1, JobID: 10, JobStatus: StatusSucceeded, ObjectKey: "k-oldest", CreatedAt: now.Add(-5 * time.Hour)},
		{ArtifactID: 4, JobID: 40, JobStatus: StatusSucceeded, ObjectKey: "k-new-2", CreatedAt: now.Add(-2 * time.Hour)},
		{ArtifactID: 2, JobID: 20, JobStatus: StatusSucceeded, ObjectKey: "k-old-2", CreatedAt: now.Add(-4 * time.Hour)},
		{ArtifactID: 5, JobID: 50, JobStatus: StatusSucceeded, ObjectKey: "k-newest", CreatedAt: now.Add(-1 * time.Hour)},
		{ArtifactID: 3, JobID: 30, JobStatus: StatusSucceeded, ObjectKey: "k-new-3", CreatedAt: now.Add(-3 * time.Hour)},
	}

	// Keep 3 newest -> prune oldest 2 (JobID 20 and 10)
	expired := SelectExpiredBackupJobs(candidates, RetentionPolicy{KeepLast: 3}, now)
	if len(expired) != 2 {
		t.Fatalf("expected 2 expired backups for KeepLast=3, got %d (%+v)", len(expired), expired)
	}
	if expired[0].JobID != 20 || expired[1].JobID != 10 {
		t.Fatalf("expired JobIDs = [%d, %d], want [20, 10]", expired[0].JobID, expired[1].JobID)
	}

	// Safe when count <= KeepLast
	none := SelectExpiredBackupJobs(candidates[:3], RetentionPolicy{KeepLast: 3}, now)
	if len(none) != 0 {
		t.Fatalf("expected 0 expired when count == KeepLast, got %d", len(none))
	}
}

func TestSelectExpiredBackupJobs_MaxAgeAndCombined(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	candidates := []RetentionCandidate{
		{ArtifactID: 1, JobID: 1, JobStatus: StatusSucceeded, ObjectKey: "k-1d", CreatedAt: now.Add(-1 * 24 * time.Hour)},
		{ArtifactID: 2, JobID: 2, JobStatus: StatusSucceeded, ObjectKey: "k-6d", CreatedAt: now.Add(-6 * 24 * time.Hour)},
		{ArtifactID: 3, JobID: 3, JobStatus: StatusSucceeded, ObjectKey: "k-7d-exact", CreatedAt: now.Add(-7 * 24 * time.Hour)},
		{ArtifactID: 4, JobID: 4, JobStatus: StatusSucceeded, ObjectKey: "k-10d", CreatedAt: now.Add(-10 * 24 * time.Hour)},
	}

	// MaxAgeDays = 7 only -> prune 7d-exact and 10d
	byAge := SelectExpiredBackupJobs(candidates, RetentionPolicy{MaxAgeDays: 7}, now)
	if len(byAge) != 2 || byAge[0].JobID != 3 || byAge[1].JobID != 4 {
		t.Fatalf("MaxAgeDays=7 expired = %+v, want JobIDs [3, 4]", byAge)
	}

	// Combined: KeepLast=1 + MaxAgeDays=7 -> keeps only 1d (JobID 1), prunes 6d (by count), 7d, 10d
	combined := SelectExpiredBackupJobs(candidates, RetentionPolicy{KeepLast: 1, MaxAgeDays: 7}, now)
	if len(combined) != 3 || combined[0].JobID != 2 || combined[1].JobID != 3 || combined[2].JobID != 4 {
		t.Fatalf("Combined expired = %+v, want JobIDs [2, 3, 4]", combined)
	}
}

func TestSelectExpiredBackupJobs_IgnoresNonSucceededAndAlreadyPruned(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	prunedAt := now.Add(-time.Hour)

	candidates := []RetentionCandidate{
		{ArtifactID: 1, JobID: 1, JobStatus: StatusQueued, ObjectKey: "k-q", CreatedAt: now.Add(-30 * 24 * time.Hour)},
		{ArtifactID: 2, JobID: 2, JobStatus: StatusRunning, ObjectKey: "k-r", CreatedAt: now.Add(-30 * 24 * time.Hour)},
		{ArtifactID: 3, JobID: 3, JobStatus: StatusVerifying, ObjectKey: "k-v", CreatedAt: now.Add(-30 * 24 * time.Hour)},
		{ArtifactID: 4, JobID: 4, JobStatus: StatusFailed, ObjectKey: "k-f", CreatedAt: now.Add(-30 * 24 * time.Hour)},
		{ArtifactID: 5, JobID: 5, JobStatus: StatusSucceeded, ObjectKey: "k-already-pruned", CreatedAt: now.Add(-30 * 24 * time.Hour), PrunedAt: &prunedAt},
		{ArtifactID: 6, JobID: 6, JobStatus: StatusSucceeded, ObjectKey: "", CreatedAt: now.Add(-30 * 24 * time.Hour)},
		{ArtifactID: 7, JobID: 7, JobStatus: StatusSucceeded, ObjectKey: "k-ok-newest", CreatedAt: now.Add(-1 * time.Hour)},
	}

	expired := SelectExpiredBackupJobs(candidates, RetentionPolicy{KeepLast: 1, MaxAgeDays: 7}, now)
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired backups (active/failed/pruned/empty must never be pruned), got %+v", expired)
	}
}
