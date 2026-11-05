package users

import (
	"context"
	"strings"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
	"github.com/Davysongs/TopChoiceBank/internal/users/domain"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
)

type AddressInput struct {
	Line1       string `json:"line1"`
	Line2       string `json:"line2,omitempty"`
	City        string `json:"city"`
	Region      string `json:"region,omitempty"`
	PostalCode  string `json:"postal_code,omitempty"`
	CountryCode string `json:"country_code"`
}

type CreateProfileRequest struct {
	UserID          string       `json:"user_id"`
	LegalGivenName  string       `json:"legal_given_name"`
	LegalFamilyName string       `json:"legal_family_name"`
	DateOfBirth     string       `json:"date_of_birth"` // YYYY-MM-DD
	PhoneE164       string       `json:"phone_e164"`
	Address         AddressInput `json:"address"`
}

type UpdateProfileRequest struct {
	PhoneE164 *string       `json:"phone_e164,omitempty"`
	Address   *AddressInput `json:"address,omitempty"`
}

type AddressResponse struct {
	Line1       string `json:"line1"`
	Line2       string `json:"line2,omitempty"`
	City        string `json:"city"`
	Region      string `json:"region,omitempty"`
	PostalCode  string `json:"postal_code,omitempty"`
	CountryCode string `json:"country_code"`
}

type ProfileResponse struct {
	ID              string          `json:"id"`
	EmailMasked     string          `json:"email_masked,omitempty"`
	LegalName       string          `json:"legal_name"`
	PhoneMasked     string          `json:"phone_masked"`
	Address         AddressResponse `json:"address"`
	OnboardingState string          `json:"onboarding_state"`
	Version         int64           `json:"version"`
}

// Service coordinates customer profile operations and event emissions.
type Service struct {
	repo         Repository
	identityRepo identity.Repository
}

// NewService constructs a customer profile application service.
func NewService(repo Repository, identityRepo identity.Repository) *Service {
	return &Service{
		repo:         repo,
		identityRepo: identityRepo,
	}
}

// CreateProfile creates and persists a new profile aggregate, emitting users.profile_created.v1.
func (s *Service) CreateProfile(ctx context.Context, req CreateProfileRequest) (*ProfileResponse, error) {
	now := time.Now().UTC()

	legalName, err := domain.NewLegalName(req.LegalGivenName, req.LegalFamilyName)
	if err != nil {
		return nil, err
	}

	dob, err := domain.ParseDateOfBirth(req.DateOfBirth, now)
	if err != nil {
		return nil, err
	}

	phone, err := domain.NewPhone(req.PhoneE164)
	if err != nil {
		return nil, err
	}

	address, err := domain.NewAddress(
		req.Address.Line1,
		req.Address.Line2,
		req.Address.City,
		req.Address.Region,
		req.Address.PostalCode,
		req.Address.CountryCode,
	)
	if err != nil {
		return nil, err
	}

	profile, err := domain.NewProfile(req.UserID, legalName, dob, phone, address, now)
	if err != nil {
		return nil, err
	}

	outboxEvent := platformdb.OutboxEventInput{
		AggregateType:    "users.user_profiles",
		AggregateID:      profile.UserID(),
		AggregateVersion: profile.Version(),
		EventType:        "users.profile_created.v1",
		SchemaVersion:    1,
		Payload: map[string]any{
			"user_id":           profile.UserID(),
			"legal_given_name":  profile.LegalName().GivenName(),
			"legal_family_name": profile.LegalName().FamilyName(),
			"date_of_birth":     profile.DateOfBirth().String(),
			"phone_e164":        profile.Phone().Value(),
			"onboarding_state":  string(profile.OnboardingState()),
			"version":           profile.Version(),
		},
		OccurredAt: now,
	}

	if err := s.repo.CreateProfileWithOutbox(ctx, profile, outboxEvent); err != nil {
		return nil, err
	}

	emailMasked := ""
	if s.identityRepo != nil {
		if u, err := s.identityRepo.GetUserByID(ctx, profile.UserID()); err == nil && u != nil {
			emailMasked = maskEmail(u.Email)
		}
	}

	return toProfileResponse(profile, emailMasked), nil
}

// GetProfile retrieves the authenticated user's profile and formats masked data.
func (s *Service) GetProfile(ctx context.Context, userID string) (*ProfileResponse, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, domain.ErrEmptyUserID
	}

	profile, err := s.repo.GetProfileByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	emailMasked := ""
	if s.identityRepo != nil {
		if u, err := s.identityRepo.GetUserByID(ctx, userID); err == nil && u != nil {
			emailMasked = maskEmail(u.Email)
		}
	}

	return toProfileResponse(profile, emailMasked), nil
}

// UpdateProfile performs optimistic-locking updates on mutable contact data, emitting users.profile_updated.v1.
func (s *Service) UpdateProfile(ctx context.Context, userID string, expectedVersion int64, req UpdateProfileRequest) (*ProfileResponse, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, domain.ErrEmptyUserID
	}
	if expectedVersion < 1 {
		return nil, ErrVersionConflict
	}
	if req.PhoneE164 == nil && req.Address == nil {
		return s.GetProfile(ctx, userID)
	}

	profile, err := s.repo.GetProfileByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if profile.Version() != expectedVersion {
		return nil, ErrVersionConflict
	}

	now := time.Now().UTC()

	var newPhone domain.Phone
	if req.PhoneE164 != nil {
		p, err := domain.NewPhone(*req.PhoneE164)
		if err != nil {
			return nil, err
		}
		newPhone = p
	} else {
		newPhone = profile.Phone()
	}

	var newAddress domain.Address
	if req.Address != nil {
		a, err := domain.NewAddress(
			req.Address.Line1,
			req.Address.Line2,
			req.Address.City,
			req.Address.Region,
			req.Address.PostalCode,
			req.Address.CountryCode,
		)
		if err != nil {
			return nil, err
		}
		newAddress = a
	} else {
		newAddress = profile.Address()
	}

	if err := profile.UpdateContact(newPhone, newAddress, now); err != nil {
		return nil, err
	}

	outboxPayload := map[string]any{
		"user_id": profile.UserID(),
		"version": profile.Version(),
	}

	outboxEvent := platformdb.OutboxEventInput{
		AggregateType:    "users.user_profiles",
		AggregateID:      profile.UserID(),
		AggregateVersion: profile.Version(),
		EventType:        "users.profile_updated.v1",
		SchemaVersion:    1,
		Payload:          outboxPayload,
		OccurredAt:       now,
	}

	if err := s.repo.UpdateProfileWithOutbox(ctx, profile, expectedVersion, outboxEvent); err != nil {
		return nil, err
	}

	emailMasked := ""
	if s.identityRepo != nil {
		if u, err := s.identityRepo.GetUserByID(ctx, userID); err == nil && u != nil {
			emailMasked = maskEmail(u.Email)
		}
	}

	return toProfileResponse(profile, emailMasked), nil
}

func toProfileResponse(profile *domain.Profile, emailMasked string) *ProfileResponse {
	return &ProfileResponse{
		ID:          profile.UserID(),
		EmailMasked: emailMasked,
		LegalName:   profile.LegalName().FullName(),
		PhoneMasked: profile.Phone().Masked(),
		Address: AddressResponse{
			Line1:       profile.Address().Line1(),
			Line2:       profile.Address().Line2(),
			City:        profile.Address().City(),
			Region:      profile.Address().Region(),
			PostalCode:  profile.Address().PostalCode(),
			CountryCode: profile.Address().CountryCode(),
		},
		OnboardingState: string(profile.OnboardingState()),
		Version:         profile.Version(),
	}
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || len(parts[0]) == 0 {
		return email
	}
	name := parts[0]
	domainPart := parts[1]
	if len(name) <= 2 {
		return name[:1] + "***@" + domainPart
	}
	return name[:1] + "***" + name[len(name)-1:] + "@" + domainPart
}
