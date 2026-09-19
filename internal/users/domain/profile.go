package domain

import (
	"strings"
	"time"
)

// OnboardingState represents the KYC and compliance onboarding state of a customer profile.
type OnboardingState string

const (
	OnboardingStatePending     OnboardingState = "PENDING"
	OnboardingStateUnderReview OnboardingState = "UNDER_REVIEW"
	OnboardingStateApproved    OnboardingState = "APPROVED"
	OnboardingStateRejected    OnboardingState = "REJECTED"
)

// Profile represents a customer's personal profile aggregate root.
// It encapsulates legal identity (LegalName, DateOfBirth) and mutable contact information (Phone, Address),
// along with the onboarding verification lifecycle.
type Profile struct {
	userID                string
	legalName             LegalName
	dateOfBirth           DateOfBirth
	phone                 Phone
	address               Address
	onboardingState       OnboardingState
	onboardingSubmittedAt *time.Time
	onboardingDecidedAt   *time.Time
	version               int64
	createdAt             time.Time
	updatedAt             time.Time
}

// NewProfile creates a new customer Profile aggregate in the initial PENDING onboarding state.
func NewProfile(
	userID string,
	legalName LegalName,
	dob DateOfBirth,
	phone Phone,
	address Address,
	now time.Time,
) (*Profile, error) {
	trimmedUserID := strings.TrimSpace(userID)
	if trimmedUserID == "" {
		return nil, ErrEmptyUserID
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	return &Profile{
		userID:          trimmedUserID,
		legalName:       legalName,
		dateOfBirth:     dob,
		phone:           phone,
		address:         address,
		onboardingState: OnboardingStatePending,
		version:         1,
		createdAt:       now,
		updatedAt:       now,
	}, nil
}

// ReconstituteProfile rebuilds a Profile instance from persistent storage,
// validating structural and relational database constraints.
func ReconstituteProfile(
	userID string,
	legalName LegalName,
	dob DateOfBirth,
	phone Phone,
	address Address,
	onboardingState OnboardingState,
	submittedAt *time.Time,
	decidedAt *time.Time,
	version int64,
	createdAt time.Time,
	updatedAt time.Time,
) (*Profile, error) {
	trimmedUserID := strings.TrimSpace(userID)
	if trimmedUserID == "" {
		return nil, ErrEmptyUserID
	}

	// Database invariant: CHECK (onboarding_decided_at IS NULL OR onboarding_submitted_at IS NOT NULL)
	if decidedAt != nil && submittedAt == nil {
		return nil, ErrInvalidOnboardingTransition
	}

	return &Profile{
		userID:                trimmedUserID,
		legalName:             legalName,
		dateOfBirth:           dob,
		phone:                 phone,
		address:               address,
		onboardingState:       onboardingState,
		onboardingSubmittedAt: submittedAt,
		onboardingDecidedAt:   decidedAt,
		version:               version,
		createdAt:             createdAt,
		updatedAt:             updatedAt,
	}, nil
}

// UserID returns the associated identity user ID.
func (p *Profile) UserID() string {
	return p.userID
}

// LegalName returns the customer's legal name value object.
func (p *Profile) LegalName() LegalName {
	return p.legalName
}

// DateOfBirth returns the customer's date of birth value object.
func (p *Profile) DateOfBirth() DateOfBirth {
	return p.dateOfBirth
}

// Phone returns the customer's contact phone number value object.
func (p *Profile) Phone() Phone {
	return p.phone
}

// Address returns the customer's residential address value object.
func (p *Profile) Address() Address {
	return p.address
}

// OnboardingState returns the current onboarding state.
func (p *Profile) OnboardingState() OnboardingState {
	return p.onboardingState
}

// OnboardingSubmittedAt returns the timestamp when onboarding was submitted for review.
func (p *Profile) OnboardingSubmittedAt() *time.Time {
	return p.onboardingSubmittedAt
}

// OnboardingDecidedAt returns the timestamp when onboarding reached a terminal decision.
func (p *Profile) OnboardingDecidedAt() *time.Time {
	return p.onboardingDecidedAt
}

// Version returns the optimistic concurrency control version.
func (p *Profile) Version() int64 {
	return p.version
}

// CreatedAt returns the profile creation timestamp.
func (p *Profile) CreatedAt() time.Time {
	return p.createdAt
}

// UpdatedAt returns the profile last modification timestamp.
func (p *Profile) UpdatedAt() time.Time {
	return p.updatedAt
}

// SubmitOnboarding transitions the profile to UNDER_REVIEW.
// Allowed from PENDING or REJECTED (resubmission creates a new review cycle).
func (p *Profile) SubmitOnboarding(now time.Time) error {
	if p.onboardingState == OnboardingStateApproved {
		return ErrProfileAlreadyDecided
	}
	if p.onboardingState == OnboardingStateUnderReview {
		return ErrInvalidOnboardingTransition
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	p.onboardingState = OnboardingStateUnderReview
	p.onboardingSubmittedAt = &now
	p.onboardingDecidedAt = nil
	p.updatedAt = now
	p.version++
	return nil
}

// ApproveOnboarding marks onboarding as APPROVED.
// Allowed only when the profile is currently UNDER_REVIEW.
func (p *Profile) ApproveOnboarding(now time.Time) error {
	if p.onboardingState != OnboardingStateUnderReview {
		return ErrInvalidOnboardingTransition
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	p.onboardingState = OnboardingStateApproved
	p.onboardingDecidedAt = &now
	p.updatedAt = now
	p.version++
	return nil
}

// RejectOnboarding marks onboarding as REJECTED.
// Allowed only when the profile is currently UNDER_REVIEW.
func (p *Profile) RejectOnboarding(now time.Time) error {
	if p.onboardingState != OnboardingStateUnderReview {
		return ErrInvalidOnboardingTransition
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	p.onboardingState = OnboardingStateRejected
	p.onboardingDecidedAt = &now
	p.updatedAt = now
	p.version++
	return nil
}

// UpdateContact updates mutable contact fields (phone and address) using optimistic locking.
func (p *Profile) UpdateContact(phone Phone, address Address, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	p.phone = phone
	p.address = address
	p.updatedAt = now
	p.version++
	return nil
}

// UpdatePhone updates the customer's phone number and advances version.
func (p *Profile) UpdatePhone(phone Phone, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	p.phone = phone
	p.updatedAt = now
	p.version++
	return nil
}

// UpdateAddress updates the customer's residential address and advances version.
func (p *Profile) UpdateAddress(address Address, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	p.address = address
	p.updatedAt = now
	p.version++
	return nil
}
