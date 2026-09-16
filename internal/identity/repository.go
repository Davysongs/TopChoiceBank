package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Davysongs/TopChoiceBank/internal/identity/domain"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	"github.com/lib/pq"
)

var (
	ErrUserNotFound          = errors.New("user not found")
	ErrDuplicateEmail        = errors.New("email already registered")
	ErrSessionNotFound       = errors.New("session not found")
	ErrFamilyNotFound        = errors.New("refresh family not found")
	ErrSessionAlreadyRevoked = errors.New("session already revoked or rotated")
)

type Repository interface {
	CreateUserWithOutbox(ctx context.Context, user *domain.User, outboxEvent platformdb.OutboxEventInput) error
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	GetUserByID(ctx context.Context, id string) (*domain.User, error)
	UpdateUserStatusAndLockout(ctx context.Context, user *domain.User) error
	CreateSessionAndFamily(ctx context.Context, family *domain.RefreshFamily, session *domain.Session) error
	GetSessionAndFamilyByRefreshTokenHash(ctx context.Context, refreshHash []byte) (*domain.SessionAggregate, error)
	RotateSession(ctx context.Context, oldSessionID string, agg *domain.SessionAggregate, rotatedSession *domain.Session) error
	RevokeRefreshFamily(ctx context.Context, familyID string, reason string) error
	RecordSecurityEvent(ctx context.Context, userID string, eventType string, outcome string, requestID string, sourceIP string, metadata map[string]any) error
	GetOrCreateDevice(ctx context.Context, userID string, fingerprintHash []byte, userAgent string, ip string) (string, error)
}

type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates an identity repository backed by db.
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// CreateUserWithOutbox persists a user, its default role, and an outbox event atomically.
func (r *PostgresRepository) CreateUserWithOutbox(ctx context.Context, user *domain.User, outboxEvent platformdb.OutboxEventInput) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	userQuery := `
		INSERT INTO identity.users (
			id, email, password_hash, password_hash_algorithm, status,
			password_changed_at, version, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = tx.ExecContext(
		ctx,
		userQuery,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.PasswordHashAlgorithm,
		user.Status,
		user.PasswordChangedAt,
		user.Version,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return fmt.Errorf("%w: %v", ErrDuplicateEmail, err)
		}
		return err
	}

	roleQuery := `
		INSERT INTO identity.user_roles (user_id, role_id, granted_at)
		SELECT $1, id, $2 FROM identity.roles WHERE name = 'customer'
	`
	_, err = tx.ExecContext(ctx, roleQuery, user.ID, user.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to assign default role: %w", err)
	}

	if err := platformdb.AppendOutboxEvent(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("failed to append registration outbox event: %w", err)
	}

	return tx.Commit()
}

// GetUserByEmail retrieves a user by their normalized email address.
func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, password_hash, password_hash_algorithm, status,
		       email_verified_at, failed_login_count, failed_login_window_started_at,
		       locked_until, password_changed_at, version, created_at, updated_at
		FROM identity.users
		WHERE email = LOWER($1)
	`
	row := r.db.QueryRowContext(ctx, query, email)

	var u domain.User
	var statusStr string
	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.PasswordHashAlgorithm,
		&statusStr,
		&u.EmailVerifiedAt,
		&u.FailedLoginCount,
		&u.FailedLoginWindowStart,
		&u.LockedUntil,
		&u.PasswordChangedAt,
		&u.Version,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	u.Status = domain.UserStatus(statusStr)
	return &u, nil
}

// GetUserByID retrieves a user by ID.
func (r *PostgresRepository) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	query := `
		SELECT id, email, password_hash, password_hash_algorithm, status,
		       email_verified_at, failed_login_count, failed_login_window_started_at,
		       locked_until, password_changed_at, version, created_at, updated_at
		FROM identity.users
		WHERE id = $1
	`
	row := r.db.QueryRowContext(ctx, query, id)

	var u domain.User
	var statusStr string
	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.PasswordHashAlgorithm,
		&statusStr,
		&u.EmailVerifiedAt,
		&u.FailedLoginCount,
		&u.FailedLoginWindowStart,
		&u.LockedUntil,
		&u.PasswordChangedAt,
		&u.Version,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	u.Status = domain.UserStatus(statusStr)
	return &u, nil
}

// UpdateUserStatusAndLockout persists a user's authentication status using optimistic concurrency.
func (r *PostgresRepository) UpdateUserStatusAndLockout(ctx context.Context, user *domain.User) error {
	query := `
		UPDATE identity.users
		SET status = $1,
		    failed_login_count = $2,
		    failed_login_window_started_at = $3,
		    locked_until = $4,
		    version = version + 1,
		    updated_at = $5
		WHERE id = $6 AND version = $7
	`
	res, err := r.db.ExecContext(
		ctx,
		query,
		string(user.Status),
		user.FailedLoginCount,
		user.FailedLoginWindowStart,
		user.LockedUntil,
		user.UpdatedAt,
		user.ID,
		user.Version,
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("concurrent modification error for user %s", user.ID)
	}
	user.Version++
	return nil
}

// CreateSessionAndFamily persists a refresh-token family and its initial session atomically.
func (r *PostgresRepository) CreateSessionAndFamily(ctx context.Context, family *domain.RefreshFamily, session *domain.Session) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	familyQuery := `
		INSERT INTO identity.refresh_families (
			id, user_id, reason, revoked_at, revoked_reason, last_used_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = tx.ExecContext(
		ctx,
		familyQuery,
		family.ID,
		family.UserID,
		family.Reason,
		family.RevokedAt,
		family.RevokedWhy,
		family.LastUsedAt,
		family.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert refresh family: %w", err)
	}

	sessionQuery := `
		INSERT INTO identity.sessions (
			id, user_id, device_id, refresh_family_id, access_token_jti,
			refresh_token_hash, rotated_from_session_id, issued_at, expires_at,
			last_used_at, revoked_at, revoke_reason, created_ip, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	_, err = tx.ExecContext(
		ctx,
		sessionQuery,
		session.ID,
		session.UserID,
		session.DeviceID,
		session.RefreshFamilyID,
		session.AccessTokenJTI,
		[]byte(session.RefreshTokenHash),
		session.RotatedFromSessionID,
		session.IssuedAt,
		session.ExpiresAt,
		session.LastUsedAt,
		session.RevokedAt,
		session.RevokeReason,
		session.CreatedIP,
		session.UserAgent,
		session.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert session: %w", err)
	}

	return tx.Commit()
}

// GetSessionAndFamilyByRefreshTokenHash retrieves a session and its refresh-token family.
func (r *PostgresRepository) GetSessionAndFamilyByRefreshTokenHash(ctx context.Context, refreshHash []byte) (*domain.SessionAggregate, error) {
	query := `
		SELECT s.id, s.user_id, s.device_id, s.refresh_family_id, s.access_token_jti,
		       s.refresh_token_hash, s.rotated_from_session_id, s.issued_at, s.expires_at,
		       s.last_used_at, s.revoked_at, s.revoke_reason, s.created_ip, s.user_agent,
		       s.created_at,
		       f.id, f.user_id, f.reason, f.revoked_at, f.revoked_reason, f.last_used_at, f.created_at
		FROM identity.sessions s
		JOIN identity.refresh_families f ON s.refresh_family_id = f.id
		WHERE s.refresh_token_hash = $1
	`
	row := r.db.QueryRowContext(ctx, query, refreshHash)

	var s domain.Session
	var f domain.RefreshFamily
	var rawHash []byte

	err := row.Scan(
		&s.ID,
		&s.UserID,
		&s.DeviceID,
		&s.RefreshFamilyID,
		&s.AccessTokenJTI,
		&rawHash,
		&s.RotatedFromSessionID,
		&s.IssuedAt,
		&s.ExpiresAt,
		&s.LastUsedAt,
		&s.RevokedAt,
		&s.RevokeReason,
		&s.CreatedIP,
		&s.UserAgent,
		&s.CreatedAt,
		&f.ID,
		&f.UserID,
		&f.Reason,
		&f.RevokedAt,
		&f.RevokedWhy,
		&f.LastUsedAt,
		&f.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	} else if err != nil {
		return nil, err
	}

	s.RefreshTokenHash = string(rawHash)
	return domain.NewSessionAggregate(&f, &s)
}

// RotateSession revokes an existing session and stores its replacement atomically.
func (r *PostgresRepository) RotateSession(ctx context.Context, oldSessionID string, agg *domain.SessionAggregate, rotatedSession *domain.Session) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Revoke old session
	revokeOldQuery := `
		UPDATE identity.sessions
		SET revoked_at = $1, revoke_reason = $2
		WHERE id = $3 AND revoked_at IS NULL
	`
	res, err := tx.ExecContext(ctx, revokeOldQuery, rotatedSession.IssuedAt, "rotated", oldSessionID)
	if err != nil {
		return fmt.Errorf("failed to revoke rotated session: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to revoke rotated session: %w", err)
	}
	if rows == 0 {
		return ErrSessionAlreadyRevoked
	}

	// Insert new session
	insertNewQuery := `
		INSERT INTO identity.sessions (
			id, user_id, device_id, refresh_family_id, access_token_jti,
			refresh_token_hash, rotated_from_session_id, issued_at, expires_at,
			last_used_at, revoked_at, revoke_reason, created_ip, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	_, err = tx.ExecContext(
		ctx,
		insertNewQuery,
		rotatedSession.ID,
		rotatedSession.UserID,
		rotatedSession.DeviceID,
		rotatedSession.RefreshFamilyID,
		rotatedSession.AccessTokenJTI,
		[]byte(rotatedSession.RefreshTokenHash),
		rotatedSession.RotatedFromSessionID,
		rotatedSession.IssuedAt,
		rotatedSession.ExpiresAt,
		rotatedSession.LastUsedAt,
		rotatedSession.RevokedAt,
		rotatedSession.RevokeReason,
		rotatedSession.CreatedIP,
		rotatedSession.UserAgent,
		rotatedSession.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert rotated session: %w", err)
	}

	// Update family last_used_at
	updateFamilyQuery := `
		UPDATE identity.refresh_families
		SET last_used_at = $1
		WHERE id = $2
	`
	_, err = tx.ExecContext(ctx, updateFamilyQuery, agg.Family.LastUsedAt, agg.Family.ID)
	if err != nil {
		return fmt.Errorf("failed to update refresh family: %w", err)
	}

	return tx.Commit()
}

// RevokeRefreshFamily revokes a refresh-token family and all of its active sessions.
func (r *PostgresRepository) RevokeRefreshFamily(ctx context.Context, familyID string, reason string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	updateFamilyQuery := `
		UPDATE identity.refresh_families
		SET revoked_at = COALESCE(revoked_at, clock_timestamp()),
		    revoked_reason = COALESCE(revoked_reason, $1)
		WHERE id = $2
	`
	_, err = tx.ExecContext(ctx, updateFamilyQuery, reason, familyID)
	if err != nil {
		return fmt.Errorf("failed to revoke family: %w", err)
	}

	updateSessionsQuery := `
		UPDATE identity.sessions
		SET revoked_at = COALESCE(revoked_at, clock_timestamp()),
		    revoke_reason = COALESCE(revoke_reason, $1)
		WHERE refresh_family_id = $2 AND revoked_at IS NULL
	`
	_, err = tx.ExecContext(ctx, updateSessionsQuery, reason, familyID)
	if err != nil {
		return fmt.Errorf("failed to revoke sessions in family: %w", err)
	}

	return tx.Commit()
}

// RecordSecurityEvent stores an identity-related security audit event.
func (r *PostgresRepository) RecordSecurityEvent(ctx context.Context, userID string, eventType string, outcome string, requestID string, sourceIP string, metadata map[string]any) error {
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		metadataBytes = []byte("{}")
	}

	query := `
		INSERT INTO identity.security_events (
			user_id, event_type, outcome, request_id, source_ip, metadata
		) VALUES (
			NULLIF($1, '')::uuid, $2, $3, $4, NULLIF($5, '')::inet, $6
		)
	`
	_, err = r.db.ExecContext(ctx, query, userID, eventType, outcome, requestID, sourceIP, metadataBytes)
	return err
}

func (r *PostgresRepository) GetOrCreateDevice(ctx context.Context, userID string, fingerprintHash []byte, userAgent string, ip string) (string, error) {
	displayName := strings.TrimSpace(userAgent)
	if len(displayName) > 120 {
		displayName = displayName[:120]
	}
	if displayName == "" {
		displayName = "Unknown Device"
	}

	query := `
		INSERT INTO identity.devices (
			user_id, fingerprint_hash, display_name, first_seen_at, last_seen_at, last_ip
		) VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp(), NULLIF($4, '')::inet)
		ON CONFLICT (user_id, fingerprint_hash) DO UPDATE
		SET last_seen_at = clock_timestamp(),
		    last_ip = COALESCE(EXCLUDED.last_ip, identity.devices.last_ip),
		    updated_at = clock_timestamp()
		RETURNING id
	`
	var id string
	err := r.db.QueryRowContext(ctx, query, userID, fingerprintHash, displayName, ip).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to get or create device: %w", err)
	}
	return id, nil
}
