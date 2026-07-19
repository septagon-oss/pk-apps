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
			exists = false
		}
	}

	if !exists && now.Before(p.saturatedUntil) {
		return errLoginPolicySaturated
	}
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
	state.failures++
	if state.failures >= p.failureLimit {
		state.lockedUntil = now.Add(p.lockout)
	}
	p.attempts[key] = state
}

func (p *loginAttemptPolicy) RecordSuccess(_ context.Context, tenantID, identifier string) {
	p.mu.Lock()
	delete(p.attempts, normalizedLoginAttemptKey(tenantID, identifier))
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
