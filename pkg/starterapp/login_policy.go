// Implements: REQ-AUTH-001.
// Per: ADR-0009.
// Discipline: C-14.

package starterapp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	starterLoginFailureLimit  = 5
	starterLoginFailureWindow = 15 * time.Minute
	starterLoginLockout       = 15 * time.Minute
	starterLoginTrackedLimit  = 8192
)

var (
	errLoginTemporarilyLocked = errors.New("starterapp: login temporarily locked")
	errLoginPolicySaturated   = errors.New("starterapp: login policy capacity reached")
)

type loginAttemptKey struct {
	tenantID   string
	identifier string
}

type loginAttemptState struct {
	failures      int
	pending       int
	windowStarted time.Time
	lockedUntil   time.Time
}

// loginAttemptPolicy is the starter host's bounded, in-memory implementation
// of auth.LoginPolicy. Production overlays can replace the host composition
// with a distributed policy, while the starter still fails closed under
// repeated credential failures and identifier-spray pressure.
type loginAttemptPolicy struct {
	mu             sync.Mutex
	now            func() time.Time
	failureLimit   int
	failureWindow  time.Duration
	lockout        time.Duration
	trackedLimit   int
	attempts       map[loginAttemptKey]loginAttemptState
	saturatedUntil time.Time
}

func newLoginAttemptPolicy() *loginAttemptPolicy {
	return &loginAttemptPolicy{
		now:           time.Now,
		failureLimit:  starterLoginFailureLimit,
		failureWindow: starterLoginFailureWindow,
		lockout:       starterLoginLockout,
		trackedLimit:  starterLoginTrackedLimit,
		attempts:      make(map[loginAttemptKey]loginAttemptState),
	}
}

func (p *loginAttemptPolicy) AllowLogin(ctx context.Context, tenantID, identifier string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	key := normalizedLoginAttemptKey(tenantID, identifier)
	now := p.now()

	p.mu.Lock()
	defer p.mu.Unlock()

	state, exists := p.attempts[key]
	if exists {
		if now.Before(state.lockedUntil) {
			return errLoginTemporarilyLocked
		}
		if !now.Before(state.windowStarted.Add(p.failureWindow)) {
			delete(p.attempts, key)
			state = loginAttemptState{}
			exists = false
		}
	}

	// Count in-flight attempts (pending) alongside recorded failures so a
	// concurrent burst cannot slip more than failureLimit attempts past the
	// gate before any of them has recorded its failure. Once the combined
	// count reaches the limit we lock immediately instead of admitting the
	// attempt — closing the check-then-record race.
	if state.failures+state.pending >= p.failureLimit {
		if !now.Before(state.lockedUntil) {
			state.lockedUntil = now.Add(p.lockout)
		}
		if !exists {
			state.windowStarted = now
		}
		p.attempts[key] = state
		return errLoginTemporarilyLocked
	}

	if !exists {
		if now.Before(p.saturatedUntil) {
			return errLoginPolicySaturated
		}
		if len(p.attempts) >= p.trackedLimit {
			p.pruneExpired(now)
			if len(p.attempts) >= p.trackedLimit {
				p.saturatedUntil = now.Add(p.failureWindow)
				return errLoginPolicySaturated
			}
		}
		state.windowStarted = now
	}

	// Reserve a slot for this in-flight attempt. RecordFailure or
	// RecordSuccess releases it; the auth service guarantees exactly one of
	// those runs for every admitted attempt.
	state.pending++
	p.attempts[key] = state
	return nil
}

func (p *loginAttemptPolicy) RecordFailure(_ context.Context, tenantID, identifier string) {
	key := normalizedLoginAttemptKey(tenantID, identifier)
	now := p.now()

	p.mu.Lock()
	defer p.mu.Unlock()

	state, exists := p.attempts[key]
	if exists && (!state.lockedUntil.IsZero() && !now.Before(state.lockedUntil) ||
		!now.Before(state.windowStarted.Add(p.failureWindow))) {
		delete(p.attempts, key)
		state = loginAttemptState{}
		exists = false
	}

	if !exists && len(p.attempts) >= p.trackedLimit {
		p.pruneExpired(now)
		if len(p.attempts) >= p.trackedLimit {
			p.saturatedUntil = now.Add(p.failureWindow)
			return
		}
	}

	if !exists {
		state.windowStarted = now
	}
	if state.pending > 0 {
		state.pending--
	}
	state.failures++
	if state.failures >= p.failureLimit {
		state.lockedUntil = now.Add(p.lockout)
	}
	p.attempts[key] = state
}

func (p *loginAttemptPolicy) RecordSuccess(_ context.Context, tenantID, identifier string) {
	key := normalizedLoginAttemptKey(tenantID, identifier)
	p.mu.Lock()
	if state, ok := p.attempts[key]; ok {
		if state.pending > 0 {
			state.pending--
		}
		if state.pending <= 0 {
			// No other attempt is in flight for this identifier: drop the entry
			// so a successful login fully clears its throttle footprint.
			delete(p.attempts, key)
		} else {
			// Correct credentials clear the recorded failures and any lock, but
			// keep the entry alive for the other in-flight attempts that still
			// hold a pending reservation.
			state.failures = 0
			state.lockedUntil = time.Time{}
			p.attempts[key] = state
		}
	}
	if len(p.attempts) < p.trackedLimit {
		p.saturatedUntil = time.Time{}
	}
	p.mu.Unlock()
}

func (p *loginAttemptPolicy) pruneExpired(now time.Time) {
	for key, state := range p.attempts {
		expiresAt := state.windowStarted.Add(p.failureWindow)
		if state.lockedUntil.After(expiresAt) {
			expiresAt = state.lockedUntil
		}
		if !now.Before(expiresAt) {
			delete(p.attempts, key)
		}
	}
}

func normalizedLoginAttemptKey(tenantID, identifier string) loginAttemptKey {
	return loginAttemptKey{
		tenantID:   strings.TrimSpace(tenantID),
		identifier: strings.ToLower(strings.TrimSpace(identifier)),
	}
}
