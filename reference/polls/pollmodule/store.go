// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Store is the persistence boundary consumed by the poll service. Mutating
// operations accept an audit entry so domain state and its audit outbox record
// commit atomically.
type Store interface {
	Create(ctx context.Context, poll *Poll, audit *AuditEntry) error
	Update(ctx context.Context, poll *Poll, audit *AuditEntry) error
	Get(ctx context.Context, tenantID, id string) (*Poll, error)
	GetBySlug(ctx context.Context, slug string) (*Poll, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]Poll, int, error)
	Delete(ctx context.Context, tenantID, id string, audit *AuditEntry) error
	SaveVote(ctx context.Context, vote *Vote) error
	GetVote(ctx context.Context, pollID, voterID string) (int, bool, error)
	CountVotes(ctx context.Context, pollID string) (map[int]int, error)
	PendingAudit(ctx context.Context, limit int) ([]AuditEntry, error)
	MarkAuditDelivered(ctx context.Context, eventID string, deliveredAt time.Time) error
	VoterSecret(ctx context.Context) ([]byte, error)
	Ping(ctx context.Context) error
}

type sqliteStore struct {
	db *sql.DB
}

// NewSQLiteStore applies embedded, append-only migrations to a caller-owned
// shared database. The returned store never closes db.
func NewSQLiteStore(db *sql.DB) (Store, error) {
	if db == nil {
		return nil, errors.New("poll: nil database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migratePollSchema(ctx, db); err != nil {
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) Create(ctx context.Context, poll *Poll, audit *AuditEntry) error {
	options, err := json.Marshal(poll.Options)
	if err != nil {
		return fmt.Errorf("poll: encode options: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("poll: begin create: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO poll_polls
			(id, tenant_id, slug, title, options, author_id, created_at,
			 description, status, closes_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		poll.ID,
		poll.TenantID,
		poll.Slug,
		poll.Title,
		string(options),
		poll.AuthorID,
		formatTime(poll.CreatedAt),
		poll.Description,
		poll.Status,
		formatOptionalTime(poll.ClosesAt),
		formatTime(poll.UpdatedAt),
	)
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("poll: create: %w", err)
	}
	if err := enqueueAudit(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("poll: commit create: %w", err)
	}
	return nil
}

func (s *sqliteStore) Update(ctx context.Context, poll *Poll, audit *AuditEntry) error {
	options, err := json.Marshal(poll.Options)
	if err != nil {
		return fmt.Errorf("poll: encode options: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("poll: begin update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(
		ctx,
		`UPDATE poll_polls
		    SET slug = ?, title = ?, description = ?, options = ?,
		        status = ?, closes_at = ?, updated_at = ?
		  WHERE tenant_id = ? AND id = ?`,
		poll.Slug,
		poll.Title,
		poll.Description,
		string(options),
		poll.Status,
		formatOptionalTime(poll.ClosesAt),
		formatTime(poll.UpdatedAt),
		poll.TenantID,
		poll.ID,
	)
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("poll: update: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("poll: update rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	if err := enqueueAudit(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("poll: commit update: %w", err)
	}
	return nil
}

func (s *sqliteStore) Get(ctx context.Context, tenantID, id string) (*Poll, error) {
	return scanPollRow(s.db.QueryRowContext(
		ctx,
		pollSelect+` WHERE tenant_id = ? AND id = ?`,
		tenantID,
		id,
	))
}

func (s *sqliteStore) GetBySlug(ctx context.Context, slug string) (*Poll, error) {
	return scanPollRow(s.db.QueryRowContext(
		ctx,
		pollSelect+` WHERE slug = ?`,
		slug,
	))
}

func (s *sqliteStore) List(
	ctx context.Context,
	tenantID string,
	limit,
	offset int,
) ([]Poll, int, error) {
	var total int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM poll_polls WHERE tenant_id = ?`,
		tenantID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("poll: count list: %w", err)
	}
	rows, err := s.db.QueryContext(
		ctx,
		pollSelect+`
		 WHERE tenant_id = ?
		 ORDER BY created_at DESC, id
		 LIMIT ? OFFSET ?`,
		tenantID,
		limit,
		offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("poll: list: %w", err)
	}
	defer rows.Close()

	polls := make([]Poll, 0, limit)
	for rows.Next() {
		poll, err := scanPoll(rows)
		if err != nil {
			return nil, 0, err
		}
		polls = append(polls, *poll)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("poll: list rows: %w", err)
	}
	return polls, total, nil
}

func (s *sqliteStore) Delete(
	ctx context.Context,
	tenantID,
	id string,
	audit *AuditEntry,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("poll: begin delete: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM poll_votes WHERE poll_id = ?`, id); err != nil {
		return fmt.Errorf("poll: delete votes: %w", err)
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM poll_polls WHERE tenant_id = ? AND id = ?`,
		tenantID,
		id,
	)
	if err != nil {
		return fmt.Errorf("poll: delete: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("poll: delete rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	if err := enqueueAudit(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("poll: commit delete: %w", err)
	}
	return nil
}

func (s *sqliteStore) SaveVote(ctx context.Context, vote *Vote) error {
	if vote == nil || strings.TrimSpace(vote.VoterID) == "" {
		return fmt.Errorf("%w: voter identity is required", ErrValidation)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("poll: begin save vote: %w", err)
	}
	defer tx.Rollback()
	var (
		status   string
		closesAt sql.NullString
	)
	if err := tx.QueryRowContext(
		ctx,
		`SELECT status, closes_at FROM poll_polls WHERE id = ?`,
		vote.PollID,
	).Scan(&status, &closesAt); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("poll: recheck vote lifecycle: %w", err)
	}
	if status != StatusPublished {
		return ErrClosed
	}
	if closesAt.Valid && closesAt.String != "" {
		closeTime, err := parseTime(closesAt.String)
		if err != nil {
			return err
		}
		if !vote.UpdatedAt.Before(closeTime) {
			return ErrClosed
		}
	}
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO poll_votes
			(poll_id, option_index, voter_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(poll_id, voter_id)
		 DO UPDATE SET option_index = excluded.option_index,
		               updated_at = excluded.updated_at`,
		vote.PollID,
		vote.OptionIndex,
		vote.VoterID,
		formatTime(vote.CreatedAt),
		formatTime(vote.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("poll: save vote: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("poll: commit vote: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetVote(
	ctx context.Context,
	pollID,
	voterID string,
) (int, bool, error) {
	var optionIndex int
	err := s.db.QueryRowContext(
		ctx,
		`SELECT option_index FROM poll_votes WHERE poll_id = ? AND voter_id = ?`,
		pollID,
		voterID,
	).Scan(&optionIndex)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("poll: get vote: %w", err)
	}
	return optionIndex, true, nil
}

func (s *sqliteStore) CountVotes(ctx context.Context, pollID string) (map[int]int, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT option_index, COUNT(*)
		   FROM poll_votes
		  WHERE poll_id = ?
		  GROUP BY option_index`,
		pollID,
	)
	if err != nil {
		return nil, fmt.Errorf("poll: count votes: %w", err)
	}
	defer rows.Close()
	counts := make(map[int]int)
	for rows.Next() {
		var optionIndex, count int
		if err := rows.Scan(&optionIndex, &count); err != nil {
			return nil, fmt.Errorf("poll: scan vote count: %w", err)
		}
		counts[optionIndex] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("poll: count vote rows: %w", err)
	}
	return counts, nil
}

func (s *sqliteStore) PendingAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT event_id, tenant_id, actor, action, resource, details, severity, created_at
		   FROM poll_audit_outbox
		  WHERE delivered_at IS NULL
		  ORDER BY created_at, event_id
		  LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("poll: list audit outbox: %w", err)
	}
	defer rows.Close()
	entries := make([]AuditEntry, 0, limit)
	for rows.Next() {
		var entry AuditEntry
		var createdAt string
		if err := rows.Scan(
			&entry.EventID,
			&entry.TenantID,
			&entry.Actor,
			&entry.Action,
			&entry.Resource,
			&entry.Details,
			&entry.Severity,
			&createdAt,
		); err != nil {
			return nil, fmt.Errorf("poll: scan audit outbox: %w", err)
		}
		parsed, err := parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		entry.CreatedAt = parsed
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("poll: iterate audit outbox: %w", err)
	}
	return entries, nil
}

func (s *sqliteStore) MarkAuditDelivered(
	ctx context.Context,
	eventID string,
	deliveredAt time.Time,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE poll_audit_outbox
		    SET delivered_at = ?
		  WHERE event_id = ? AND delivered_at IS NULL`,
		formatTime(deliveredAt),
		eventID,
	)
	if err != nil {
		return fmt.Errorf("poll: mark audit delivered: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("poll: audit delivery rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) VoterSecret(ctx context.Context) ([]byte, error) {
	const key = "voter_cookie_hmac_v1"
	var encoded string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT value FROM poll_settings WHERE key = ?`,
		key,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("poll: generate voter secret: %w", err)
		}
		encoded = hex.EncodeToString(secret)
		_, err = s.db.ExecContext(
			ctx,
			`INSERT INTO poll_settings (key, value, created_at)
			 VALUES (?, ?, ?)
			 ON CONFLICT(key) DO NOTHING`,
			key,
			encoded,
			formatTime(time.Now().UTC()),
		)
		if err != nil {
			return nil, fmt.Errorf("poll: persist voter secret: %w", err)
		}
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT value FROM poll_settings WHERE key = ?`,
			key,
		).Scan(&encoded); err != nil {
			return nil, fmt.Errorf("poll: load persisted voter secret: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("poll: load voter secret: %w", err)
	}
	secret, err := hex.DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return nil, errors.New("poll: persisted voter secret is invalid")
	}
	return secret, nil
}

func (s *sqliteStore) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return fmt.Errorf("poll: ping store: %w", err)
	}
	return nil
}

const pollSelect = `
	SELECT id, tenant_id, slug, title, description, options, author_id,
	       status, closes_at,
	       (SELECT COUNT(*) FROM poll_votes WHERE poll_id = poll_polls.id),
	       created_at, updated_at
	  FROM poll_polls`

func scanPollRow(row *sql.Row) (*Poll, error) {
	poll, err := scanPoll(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return poll, err
}

func scanPoll(row interface{ Scan(...any) error }) (*Poll, error) {
	var (
		poll      Poll
		options   string
		closesAt  sql.NullString
		createdAt string
		updatedAt string
	)
	if err := row.Scan(
		&poll.ID,
		&poll.TenantID,
		&poll.Slug,
		&poll.Title,
		&poll.Description,
		&options,
		&poll.AuthorID,
		&poll.Status,
		&closesAt,
		&poll.VoteCount,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(options), &poll.Options); err != nil {
		return nil, fmt.Errorf("poll: decode stored options: %w", err)
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	updated, err := parseTime(updatedAt)
	if err != nil {
		return nil, err
	}
	poll.CreatedAt = created
	poll.UpdatedAt = updated
	if closesAt.Valid && closesAt.String != "" {
		value, err := parseTime(closesAt.String)
		if err != nil {
			return nil, err
		}
		poll.ClosesAt = &value
	}
	return &poll, nil
}

func enqueueAudit(ctx context.Context, tx *sql.Tx, entry *AuditEntry) error {
	if entry == nil {
		return errors.New("poll: mutation is missing its audit entry")
	}
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO poll_audit_outbox
			(event_id, tenant_id, actor, action, resource, details, severity, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.EventID,
		entry.TenantID,
		entry.Actor,
		entry.Action,
		entry.Resource,
		entry.Details,
		entry.Severity,
		formatTime(entry.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("poll: enqueue audit event: %w", err)
	}
	return nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func formatOptionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("poll: parse stored time %q: %w", value, err)
	}
	return parsed, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
