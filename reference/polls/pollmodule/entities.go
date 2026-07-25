// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

// Package pollmodule demonstrates a production-shaped extension: tenant
// ownership, lifecycle transitions, durable audit delivery, public HTML and
// API surfaces, scoped administration, and append-only SQLite migrations.
package pollmodule

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxSlugRunes        = 80
	maxTitleRunes       = 200
	maxDescriptionRunes = 2000
	maxOptionRunes      = 200
	maxOptions          = 20

	StatusDraft     = "draft"
	StatusPublished = "published"
	StatusClosed    = "closed"
	StatusArchived  = "archived"
)

var (
	ErrNotFound    = errors.New("poll: not found")
	ErrDuplicate   = errors.New("poll: duplicate slug")
	ErrValidation  = errors.New("poll: validation failed")
	ErrForbidden   = errors.New("poll: forbidden")
	ErrConflict    = errors.New("poll: lifecycle conflict")
	ErrClosed      = errors.New("poll: voting closed")
	ErrRateLimited = errors.New("poll: rate limited")

	slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// Poll is a tenant-owned poll. Public slugs are globally unique because the
// public URL intentionally has no tenant segment.
type Poll struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Slug        string     `json:"slug"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Options     []string   `json:"options"`
	AuthorID    string     `json:"author_id"`
	Status      string     `json:"status"`
	ClosesAt    *time.Time `json:"closes_at,omitempty"`
	VoteCount   int        `json:"vote_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// PublicPoll is the redacted representation returned to voters. Internal
// tenant, author, and database identifiers never cross the public boundary.
type PublicPoll struct {
	Slug        string     `json:"slug"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Options     []string   `json:"options"`
	Status      string     `json:"status"`
	ClosesAt    *time.Time `json:"closes_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// PollPage is the bounded management-list response consumed by API clients and
// the reference admin.
type PollPage struct {
	Items  []Poll `json:"items"`
	Total  int    `json:"total"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

// Vote is one browser or authenticated account's current choice on a poll.
type Vote struct {
	PollID      string
	OptionIndex int
	VoterID     string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AuditEntry is written to the poll outbox in the same transaction as an
// administrative mutation, then delivered to audit_management.
type AuditEntry struct {
	EventID   string
	TenantID  string
	Actor     string
	Action    string
	Resource  string
	Details   string
	Severity  string
	CreatedAt time.Time
}

// PollUpdate contains the fields authors may change while a poll is still a
// draft. Options become immutable once voting can begin.
type PollUpdate struct {
	Slug        string     `json:"slug"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Options     []string   `json:"options"`
	ClosesAt    *time.Time `json:"closes_at,omitempty"`
}

func (p *Poll) normalizeAndValidate() error {
	if p == nil {
		return fmt.Errorf("%w: poll is required", ErrValidation)
	}

	p.Slug = strings.ToLower(strings.TrimSpace(p.Slug))
	p.Title = strings.TrimSpace(p.Title)
	p.Description = strings.TrimSpace(p.Description)
	if p.Status == "" {
		p.Status = StatusDraft
	}
	switch {
	case p.Slug == "":
		return fmt.Errorf("%w: slug is required", ErrValidation)
	case utf8.RuneCountInString(p.Slug) > maxSlugRunes:
		return fmt.Errorf("%w: slug must be at most %d characters", ErrValidation, maxSlugRunes)
	case !slugPattern.MatchString(p.Slug):
		return fmt.Errorf("%w: slug must contain lowercase letters, numbers, and single hyphens", ErrValidation)
	case p.Title == "":
		return fmt.Errorf("%w: title is required", ErrValidation)
	case utf8.RuneCountInString(p.Title) > maxTitleRunes:
		return fmt.Errorf("%w: title must be at most %d characters", ErrValidation, maxTitleRunes)
	case utf8.RuneCountInString(p.Description) > maxDescriptionRunes:
		return fmt.Errorf("%w: description must be at most %d characters", ErrValidation, maxDescriptionRunes)
	case len(p.Options) < 2:
		return fmt.Errorf("%w: at least two options are required", ErrValidation)
	case len(p.Options) > maxOptions:
		return fmt.Errorf("%w: at most %d options are allowed", ErrValidation, maxOptions)
	case !validStatus(p.Status):
		return fmt.Errorf("%w: invalid poll status %q", ErrValidation, p.Status)
	case p.ClosesAt != nil && !p.ClosesAt.After(time.Now().UTC()):
		return fmt.Errorf("%w: closes_at must be in the future", ErrValidation)
	}

	seen := make(map[string]struct{}, len(p.Options))
	normalized := make([]string, len(p.Options))
	for i, option := range p.Options {
		option = strings.TrimSpace(option)
		switch {
		case option == "":
			return fmt.Errorf("%w: option %d is empty", ErrValidation, i)
		case utf8.RuneCountInString(option) > maxOptionRunes:
			return fmt.Errorf("%w: option %d must be at most %d characters", ErrValidation, i, maxOptionRunes)
		}
		key := strings.ToLower(option)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: options must be unique", ErrValidation)
		}
		seen[key] = struct{}{}
		normalized[i] = option
	}
	p.Options = normalized
	if p.ClosesAt != nil {
		utc := p.ClosesAt.UTC()
		p.ClosesAt = &utc
	}
	return nil
}

func validStatus(status string) bool {
	switch status {
	case StatusDraft, StatusPublished, StatusClosed, StatusArchived:
		return true
	default:
		return false
	}
}

func (p *Poll) effectiveStatus(now time.Time) string {
	if p.Status == StatusPublished && p.ClosesAt != nil && !now.Before(*p.ClosesAt) {
		return StatusClosed
	}
	return p.Status
}

func (p *Poll) acceptsVotes(now time.Time) bool {
	return p.effectiveStatus(now) == StatusPublished
}

func publicPoll(p *Poll, now time.Time) PublicPoll {
	return PublicPoll{
		Slug:        p.Slug,
		Title:       p.Title,
		Description: p.Description,
		Options:     append([]string(nil), p.Options...),
		Status:      p.effectiveStatus(now),
		ClosesAt:    cloneTime(p.ClosesAt),
		CreatedAt:   p.CreatedAt,
	}
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
