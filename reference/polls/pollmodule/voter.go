// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/septagon-oss/pk-core/pkg/security/identity"
)

const (
	voterCookieName    = "pk_poll_voter"
	voterCookieMaxAge  = 365 * 24 * 60 * 60
	voteLimitPerWindow = 30
	voteLimitWindow    = time.Minute
)

type voteBucket struct {
	windowStart time.Time
	count       int
}

type voteLimiter struct {
	mu      sync.Mutex
	buckets map[string]voteBucket
}

func newVoteLimiter() *voteLimiter {
	return &voteLimiter{buckets: make(map[string]voteBucket)}
}

func (l *voteLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket := l.buckets[key]
	if bucket.windowStart.IsZero() || now.Sub(bucket.windowStart) >= voteLimitWindow {
		bucket = voteBucket{windowStart: now, count: 1}
		l.buckets[key] = bucket
		l.evictExpired(now)
		return true, 0
	}
	if bucket.count >= voteLimitPerWindow {
		return false, voteLimitWindow - now.Sub(bucket.windowStart)
	}
	bucket.count++
	l.buckets[key] = bucket
	return true, 0
}

func (l *voteLimiter) evictExpired(now time.Time) {
	if len(l.buckets) < 512 {
		return
	}
	for key, bucket := range l.buckets {
		if now.Sub(bucket.windowStart) >= voteLimitWindow {
			delete(l.buckets, key)
		}
	}
}

func (h *Handler) voterIdentity(w http.ResponseWriter, r *http.Request) (string, error) {
	if existing := h.existingVoterIdentity(r); existing != "" {
		return existing, nil
	}
	token, err := newID()
	if err != nil {
		return "", fmt.Errorf("poll: generate voter identity: %w", err)
	}
	value := token + "." + h.signVoterToken(token)
	// #nosec G124 -- this signed cookie is an anonymous ballot-deduplication
	// hint, not authentication or authorization. Local loopback HTTP must work;
	// TLS deployments set Secure below. HttpOnly and SameSite are unconditional.
	http.SetCookie(w, &http.Cookie{
		Name:     voterCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   voterCookieMaxAge,
		Expires:  time.Now().UTC().Add(time.Duration(voterCookieMaxAge) * time.Second),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	return "browser:" + token, nil
}

func (h *Handler) existingVoterIdentity(r *http.Request) string {
	principal := identity.PrincipalFromContext(r.Context())
	if !principal.IsAnonymous() && principal.Subject != "" {
		return "account:" + principal.TenantID + ":" + principal.Subject
	}
	cookie, err := r.Cookie(voterCookieName)
	if err != nil {
		return ""
	}
	token, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok || !validVoterToken(token) {
		return ""
	}
	if !hmac.Equal([]byte(signature), []byte(h.signVoterToken(token))) {
		return ""
	}
	return "browser:" + token
}

func (h *Handler) signVoterToken(token string) string {
	mac := hmac.New(sha256.New, h.voterSecret)
	_, _ = mac.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validVoterToken(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func (h *Handler) voteRateKey(r *http.Request) string {
	address := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	if address == "" {
		address = "unknown"
	}
	mac := hmac.New(sha256.New, h.voterSecret)
	_, _ = mac.Write([]byte(address))
	return hex.EncodeToString(mac.Sum(nil))
}
