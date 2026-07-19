// Validates: REQ-AUTH-001.
// Per: ADR-0009.
// Discipline: C-14.

package starterapp

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoginAttemptPolicyLocksAndExpires(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 19, 20, 0, 0, 0, time.UTC)
	policy := newLoginAttemptPolicy()
	policy.now = func() time.Time { return now }

	for range starterLoginFailureLimit {
		if err := policy.AllowLogin(context.Background(), "tenant", "User@Example.test"); err != nil {
			t.Fatalf("AllowLogin before threshold: %v", err)
		}
		policy.RecordFailure(context.Background(), "tenant", " user@example.test ")
	}

	if err := policy.AllowLogin(context.Background(), "tenant", "USER@example.test"); !errors.Is(err, errLoginTemporarilyLocked) {
		t.Fatalf("AllowLogin after threshold = %v, want temporary lock", err)
	}

	now = now.Add(starterLoginLockout)
	if err := policy.AllowLogin(context.Background(), "tenant", "user@example.test"); err != nil {
		t.Fatalf("AllowLogin after lockout: %v", err)
	}
}

func TestLoginAttemptPolicySuccessClearsFailures(t *testing.T) {
	t.Parallel()

	policy := newLoginAttemptPolicy()
	for range starterLoginFailureLimit - 1 {
		policy.RecordFailure(context.Background(), "tenant", "user@example.test")
	}
	policy.RecordSuccess(context.Background(), "tenant", "user@example.test")

	policy.RecordFailure(context.Background(), "tenant", "user@example.test")
	if err := policy.AllowLogin(context.Background(), "tenant", "user@example.test"); err != nil {
		t.Fatalf("AllowLogin after successful reset: %v", err)
	}
}

func TestLoginAttemptPolicyHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newLoginAttemptPolicy().AllowLogin(ctx, "tenant", "user@example.test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("AllowLogin canceled context = %v, want context.Canceled", err)
	}
}
