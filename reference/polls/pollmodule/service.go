// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/septagon-oss/pk-modules/pkg/audit"
)

const auditFlushBatchSize = 100

// Service owns poll validation, lifecycle, tenant safety, authorization, and
// delivery from the durable audit outbox.
type Service struct {
	store Store
	audit audit.AuditService
	now   func() time.Time
}

// NewService creates a poll service over store. auditService may be nil for
// isolated module tests; outbox entries remain durable until a configured
// service flushes them.
func NewService(store Store, auditService audit.AuditService) *Service {
	return &Service{
		store: store,
		audit: auditService,
		now:   func() time.Time { return time.Now().UTC() },
	}
}

// Create validates and persists a new draft poll.
func (s *Service) Create(ctx context.Context, poll *Poll) error {
	if poll == nil {
		return fmt.Errorf("%w: poll is required", ErrValidation)
	}
	poll.Status = StatusDraft
	if err := poll.normalizeAndValidate(); err != nil {
		return err
	}
	if strings.TrimSpace(poll.TenantID) == "" {
		return fmt.Errorf("%w: tenant identity is required", ErrValidation)
	}
	if strings.TrimSpace(poll.AuthorID) == "" {
		return fmt.Errorf("%w: author identity is required", ErrValidation)
	}
	if poll.ID == "" {
		id, err := newID()
		if err != nil {
			return fmt.Errorf("poll: generate id: %w", err)
		}
		poll.ID = id
	}
	now := s.now()
	poll.CreatedAt = now
	poll.UpdatedAt = now
	entry, err := newAuditEntry(
		poll.TenantID,
		poll.AuthorID,
		"poll.created",
		"poll:"+poll.ID,
		map[string]any{"slug": poll.Slug, "status": poll.Status},
		now,
	)
	if err != nil {
		return err
	}
	if err := s.store.Create(ctx, poll, entry); err != nil {
		return err
	}
	addMetric("polls_created_total", 1)
	s.flushAuditBestEffort(ctx)
	return nil
}

// Get returns a poll only when it belongs to tenantID.
func (s *Service) Get(ctx context.Context, tenantID, id string) (*Poll, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return nil, ErrNotFound
	}
	return s.store.Get(ctx, tenantID, id)
}

// GetPublicBySlug returns only published or closed polls. Draft and archived
// resources deliberately look absent at the public boundary.
func (s *Service) GetPublicBySlug(ctx context.Context, slug string) (*Poll, error) {
	poll, err := s.store.GetBySlug(ctx, strings.ToLower(strings.TrimSpace(slug)))
	if err != nil {
		return nil, err
	}
	switch poll.Status {
	case StatusPublished, StatusClosed:
		return poll, nil
	default:
		return nil, ErrNotFound
	}
}

// List returns a bounded page of polls owned by tenantID.
func (s *Service) List(
	ctx context.Context,
	tenantID string,
	limit,
	offset int,
) (PollPage, error) {
	if strings.TrimSpace(tenantID) == "" {
		return PollPage{}, fmt.Errorf("%w: tenant identity is required", ErrValidation)
	}
	if limit <= 0 || limit > 100 {
		return PollPage{}, fmt.Errorf("%w: limit must be between 1 and 100", ErrValidation)
	}
	if offset < 0 {
		return PollPage{}, fmt.Errorf("%w: offset must not be negative", ErrValidation)
	}
	items, total, err := s.store.List(ctx, tenantID, limit, offset)
	if err != nil {
		return PollPage{}, err
	}
	return PollPage{Items: items, Total: total, Limit: limit, Offset: offset}, nil
}

// Update changes a poll while it is still a draft.
func (s *Service) Update(
	ctx context.Context,
	tenantID,
	actorID string,
	moderator bool,
	id string,
	input PollUpdate,
) (*Poll, error) {
	poll, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := authorizePollMutation(poll, actorID, moderator); err != nil {
		return nil, err
	}
	if poll.Status != StatusDraft {
		return nil, fmt.Errorf("%w: only draft polls can be edited", ErrConflict)
	}
	poll.Slug = input.Slug
	poll.Title = input.Title
	poll.Description = input.Description
	poll.Options = append([]string(nil), input.Options...)
	poll.ClosesAt = cloneTime(input.ClosesAt)
	if err := poll.normalizeAndValidate(); err != nil {
		return nil, err
	}
	poll.UpdatedAt = s.now()
	entry, err := newAuditEntry(
		tenantID,
		actorID,
		"poll.updated",
		"poll:"+poll.ID,
		map[string]any{"slug": poll.Slug, "status": poll.Status},
		poll.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if err := s.store.Update(ctx, poll, entry); err != nil {
		return nil, err
	}
	addMetric("polls_updated_total", 1)
	s.flushAuditBestEffort(ctx)
	return poll, nil
}

// Transition applies one of the explicit lifecycle actions.
func (s *Service) Transition(
	ctx context.Context,
	tenantID,
	actorID string,
	moderator bool,
	id,
	target string,
) (*Poll, error) {
	poll, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := authorizePollMutation(poll, actorID, moderator); err != nil {
		return nil, err
	}
	if target == StatusPublished && poll.ClosesAt != nil && !s.now().Before(*poll.ClosesAt) {
		return nil, fmt.Errorf("%w: closes_at must be in the future before publishing", ErrConflict)
	}
	if err := validateTransition(poll.Status, target); err != nil {
		return nil, err
	}
	poll.Status = target
	poll.UpdatedAt = s.now()
	entry, err := newAuditEntry(
		tenantID,
		actorID,
		"poll."+target,
		"poll:"+poll.ID,
		map[string]any{"slug": poll.Slug, "status": target},
		poll.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if err := s.store.Update(ctx, poll, entry); err != nil {
		return nil, err
	}
	addMetric("poll_transitions_total", 1)
	s.flushAuditBestEffort(ctx)
	return poll, nil
}

// Delete permanently removes drafts only. Published data moves through the
// archive transition so a moderator cannot accidentally erase live results.
func (s *Service) Delete(
	ctx context.Context,
	tenantID,
	actorID string,
	moderator bool,
	id string,
) error {
	poll, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := authorizePollMutation(poll, actorID, moderator); err != nil {
		return err
	}
	if poll.Status != StatusDraft {
		return fmt.Errorf("%w: publish history must be archived, not deleted", ErrConflict)
	}
	now := s.now()
	entry, err := newAuditEntry(
		tenantID,
		actorID,
		"poll.deleted",
		"poll:"+poll.ID,
		map[string]any{"slug": poll.Slug, "status": poll.Status},
		now,
	)
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, tenantID, id, entry); err != nil {
		return err
	}
	addMetric("polls_deleted_total", 1)
	s.flushAuditBestEffort(ctx)
	return nil
}

// Vote creates or changes one identified voter's choice.
func (s *Service) Vote(
	ctx context.Context,
	slug string,
	optionIndex int,
	voterID string,
) (*Poll, map[int]int, error) {
	poll, err := s.GetPublicBySlug(ctx, slug)
	if err != nil {
		addMetric("votes_rejected_total", 1)
		return nil, nil, err
	}
	now := s.now()
	if !poll.acceptsVotes(now) {
		addMetric("votes_rejected_total", 1)
		return nil, nil, ErrClosed
	}
	if optionIndex < 0 || optionIndex >= len(poll.Options) {
		addMetric("votes_rejected_total", 1)
		return nil, nil, fmt.Errorf("%w: option_index is out of range", ErrValidation)
	}
	if strings.TrimSpace(voterID) == "" {
		addMetric("votes_rejected_total", 1)
		return nil, nil, fmt.Errorf("%w: voter identity is required", ErrValidation)
	}
	if err := s.store.SaveVote(ctx, &Vote{
		PollID:      poll.ID,
		OptionIndex: optionIndex,
		VoterID:     voterID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		addMetric("votes_rejected_total", 1)
		return nil, nil, err
	}
	counts, err := s.store.CountVotes(ctx, poll.ID)
	if err != nil {
		return nil, nil, err
	}
	addMetric("votes_accepted_total", 1)
	return poll, counts, nil
}

func (s *Service) Results(ctx context.Context, poll *Poll) (map[int]int, error) {
	if poll == nil {
		return nil, ErrNotFound
	}
	return s.store.CountVotes(ctx, poll.ID)
}

func (s *Service) CurrentVote(
	ctx context.Context,
	pollID,
	voterID string,
) (int, bool, error) {
	if voterID == "" {
		return 0, false, nil
	}
	return s.store.GetVote(ctx, pollID, voterID)
}

// FlushAudit delivers pending outbox events in order. It is safe to call
// repeatedly; successfully delivered entries are marked in the local ledger.
func (s *Service) FlushAudit(ctx context.Context) error {
	if s.audit == nil {
		return nil
	}
	entries, err := s.store.PendingAudit(ctx, auditFlushBatchSize)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		event := &audit.Event{
			ID:        entry.EventID,
			TenantID:  entry.TenantID,
			Actor:     entry.Actor,
			Action:    entry.Action,
			Resource:  entry.Resource,
			Severity:  entry.Severity,
			Details:   entry.Details,
			EmittedAt: entry.CreatedAt,
		}
		if err := s.audit.Record(ctx, event); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "unique") {
			return fmt.Errorf("poll: deliver audit event %s: %w", entry.EventID, err)
		}
		if err := s.store.MarkAuditDelivered(ctx, entry.EventID, s.now()); err != nil {
			return err
		}
		addMetric("audit_events_delivered_total", 1)
	}
	return nil
}

func (s *Service) flushAuditBestEffort(ctx context.Context) {
	if err := s.FlushAudit(ctx); err != nil {
		addMetric("audit_delivery_failures_total", 1)
	}
}

func authorizePollMutation(poll *Poll, actorID string, moderator bool) error {
	if poll == nil {
		return ErrNotFound
	}
	if strings.TrimSpace(actorID) == "" {
		return ErrForbidden
	}
	if poll.AuthorID != actorID && !moderator {
		return ErrForbidden
	}
	return nil
}

func validateTransition(current, target string) error {
	switch {
	case current == StatusDraft && target == StatusPublished:
		return nil
	case current == StatusPublished && target == StatusClosed:
		return nil
	case current != StatusArchived && target == StatusArchived:
		return nil
	default:
		return fmt.Errorf("%w: cannot move poll from %s to %s", ErrConflict, current, target)
	}
}

func newAuditEntry(
	tenantID,
	actor,
	action,
	resource string,
	details map[string]any,
	createdAt time.Time,
) (*AuditEntry, error) {
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("poll: generate audit event id: %w", err)
	}
	body, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("poll: encode audit details: %w", err)
	}
	return &AuditEntry{
		EventID:   "poll_" + id,
		TenantID:  tenantID,
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Details:   string(body),
		Severity:  audit.SeverityInfo,
		CreatedAt: createdAt,
	}, nil
}

func isLifecycleError(err error) bool {
	return errors.Is(err, ErrConflict) || errors.Is(err, ErrClosed)
}
