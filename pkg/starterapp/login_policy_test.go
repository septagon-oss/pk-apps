// Validates: REQ-AUTH-001.
// Per: ADR-0009.
// Discipline: C-14.

package starterapp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

// TestLoginAttemptPolicyBurstIsBounded is the v0.2.2 regression for the
// check-then-record throttle race: a concurrent burst of wrong-password
// attempts against one identifier must not slip more than failureLimit past the
// gate before lockout engages. The pending-reservation counter closes the
// window where many goroutines all read a sub-threshold count before any of
// them records its failure.
func TestLoginAttemptPolicyBurstIsBounded(t *testing.T) {
	t.Parallel()

	policy := newLoginAttemptPolicy()
	const attackers = 64
	var admitted int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range attackers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := policy.AllowLogin(context.Background(), "tenant", "victim@example.test"); err == nil {
				atomic.AddInt64(&admitted, 1)
				// Every admitted attempt is a wrong password in this scenario.
				policy.RecordFailure(context.Background(), "tenant", "victim@example.test")
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&admitted); got > int64(starterLoginFailureLimit) {
		t.Fatalf("burst admitted %d attempts, want <= failureLimit=%d — throttle race is open", got, starterLoginFailureLimit)
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
