package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/users/domain"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	"github.com/lib/pq"
)

var (
	ErrProfileNotFound = errors.New("profile not found")
	ErrVersionConflict = errors.New("optimistic lock version conflict")
	ErrDuplicatePhone  = errors.New("phone number already registered")
)

// Repository defines storage operations for customer profiles and transactional events.
type Repository interface {
	CreateProfileWithOutbox(ctx context.Context, profile *domain.Profile, outboxEvent platformdb.OutboxEventInput) error
	GetProfileByUserID(ctx context.Context, userID string) (*domain.Profile, error)
	UpdateProfileWithOutbox(ctx context.Context, profile *domain.Profile, expectedVersion int64, outboxEvent platformdb.OutboxEventInput) error
}

// PostgresRepository implements Repository using PostgreSQL.
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a profile repository backed by db.
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// CreateProfileWithOutbox persists a profile and its initial outbox event atomically.
func (r *PostgresRepository) CreateProfileWithOutbox(ctx context.Context, profile *domain.Profile, outboxEvent platformdb.OutboxEventInput) error {
	if profile == nil {
		return errors.New("profile is required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO users.user_profiles (
			user_id, legal_given_name, legal_family_name, date_of_birth,
			phone_e164, address_line1, address_line2, city, region,
			postal_code, country_code, onboarding_state,
			onboarding_submitted_at, onboarding_decided_at, version,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`

	dob := profile.DateOfBirth().Time()

	_, err = tx.ExecContext(
		ctx,
		query,
		profile.UserID(),
		profile.LegalName().GivenName(),
		profile.LegalName().FamilyName(),
		dob,
		profile.Phone().Value(),
		profile.Address().Line1(),
		nullableString(profile.Address().Line2()),
		profile.Address().City(),
		nullableString(profile.Address().Region()),
		nullableString(profile.Address().PostalCode()),
		profile.Address().CountryCode(),
		string(profile.OnboardingState()),
		profile.OnboardingSubmittedAt(),
		profile.OnboardingDecidedAt(),
		profile.Version(),
		profile.CreatedAt(),
		profile.UpdatedAt(),
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return ErrDuplicatePhone
		}
		return fmt.Errorf("failed to insert user profile: %w", err)
	}

	if err := platformdb.AppendOutboxEvent(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("failed to append outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit profile transaction: %w", err)
	}

	return nil
}

// GetProfileByUserID retrieves a customer profile by user ID.
func (r *PostgresRepository) GetProfileByUserID(ctx context.Context, userID string) (*domain.Profile, error) {
	query := `
		SELECT
			user_id, legal_given_name, legal_family_name, date_of_birth,
			phone_e164, address_line1, COALESCE(address_line2, ''), city,
			COALESCE(region, ''), COALESCE(postal_code, ''), country_code,
			onboarding_state, onboarding_submitted_at, onboarding_decided_at,
			version, created_at, updated_at
		FROM users.user_profiles
		WHERE user_id = $1
	`

	var (
		uID          string
		givenName    string
		familyName   string
		dobTime      time.Time
		phoneE164    string
		line1        string
		line2        string
		city         string
		region       string
		postalCode   string
		countryCode  string
		stateStr     string
		submittedAt  *time.Time
		decidedAt    *time.Time
		version      int64
		createdAt    time.Time
		updatedAt    time.Time
	)

	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&uID,
		&givenName,
		&familyName,
		&dobTime,
		&phoneE164,
		&line1,
		&line2,
		&city,
		&region,
		&postalCode,
		&countryCode,
		&stateStr,
		&submittedAt,
		&decidedAt,
		&version,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrProfileNotFound
		}
		return nil, fmt.Errorf("failed to query user profile: %w", err)
	}

	legalName, err := domain.NewLegalName(givenName, familyName)
	if err != nil {
		return nil, fmt.Errorf("corrupt legal name in persistence: %w", err)
	}

	dob, err := domain.NewDateOfBirth(dobTime.Year(), dobTime.Month(), dobTime.Day(), dobTime)
	if err != nil {
		return nil, fmt.Errorf("corrupt date of birth in persistence: %w", err)
	}

	phone, err := domain.NewPhone(phoneE164)
	if err != nil {
		return nil, fmt.Errorf("corrupt phone number in persistence: %w", err)
	}

	address, err := domain.NewAddress(line1, line2, city, region, postalCode, countryCode)
	if err != nil {
		return nil, fmt.Errorf("corrupt address in persistence: %w", err)
	}

	profile, err := domain.ReconstituteProfile(
		uID,
		legalName,
		dob,
		phone,
		address,
		domain.OnboardingState(stateStr),
		submittedAt,
		decidedAt,
		version,
		createdAt,
		updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstitute profile: %w", err)
	}

	return profile, nil
}

// UpdateProfileWithOutbox updates mutable profile fields with optimistic concurrency control
// and appends an outbox event in the same transaction.
func (r *PostgresRepository) UpdateProfileWithOutbox(
	ctx context.Context,
	profile *domain.Profile,
	expectedVersion int64,
	outboxEvent platformdb.OutboxEventInput,
) error {
	if profile == nil {
		return errors.New("profile is required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		UPDATE users.user_profiles
		SET phone_e164 = $1,
			address_line1 = $2,
			address_line2 = $3,
			city = $4,
			region = $5,
			postal_code = $6,
			country_code = $7,
			onboarding_state = $8,
			onboarding_submitted_at = $9,
			onboarding_decided_at = $10,
			version = $11,
			updated_at = $12
		WHERE user_id = $13 AND version = $14
	`

	res, err := tx.ExecContext(
		ctx,
		query,
		profile.Phone().Value(),
		profile.Address().Line1(),
		nullableString(profile.Address().Line2()),
		profile.Address().City(),
		nullableString(profile.Address().Region()),
		nullableString(profile.Address().PostalCode()),
		profile.Address().CountryCode(),
		string(profile.OnboardingState()),
		profile.OnboardingSubmittedAt(),
		profile.OnboardingDecidedAt(),
		profile.Version(),
		profile.UpdatedAt(),
		profile.UserID(),
		expectedVersion,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return ErrDuplicatePhone
		}
		return fmt.Errorf("failed to execute profile update: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		var exists bool
		checkErr := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users.user_profiles WHERE user_id = $1)", profile.UserID()).Scan(&exists)
		if checkErr != nil {
			return fmt.Errorf("failed to check profile existence: %w", checkErr)
		}
		if !exists {
			return ErrProfileNotFound
		}
		return ErrVersionConflict
	}

	if err := platformdb.AppendOutboxEvent(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("failed to append outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit update transaction: %w", err)
	}

	return nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
