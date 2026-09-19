package domain

import "errors"

var (
	// User / Profile errors
	ErrEmptyUserID = errors.New("user id is required")

	// LegalName errors
	ErrInvalidGivenName  = errors.New("legal given name must be between 1 and 100 characters")
	ErrInvalidFamilyName = errors.New("legal family name must be between 1 and 100 characters")

	// DateOfBirth errors
	ErrInvalidDateOfBirth    = errors.New("invalid date of birth")
	ErrDateOfBirthInFuture   = errors.New("date of birth cannot be in the future")
	ErrDateOfBirthBefore1900 = errors.New("date of birth must be on or after 1900-01-01")

	// Phone errors
	ErrInvalidPhoneNumber = errors.New("phone number must be in valid E.164 format")

	// Address errors
	ErrEmptyAddressLine1    = errors.New("address line 1 is required")
	ErrAddressLine1TooLong  = errors.New("address line 1 must not exceed 255 characters")
	ErrAddressLine2TooLong  = errors.New("address line 2 must not exceed 255 characters")
	ErrEmptyCity            = errors.New("city is required")
	ErrCityTooLong          = errors.New("city must not exceed 100 characters")
	ErrRegionTooLong        = errors.New("region must not exceed 100 characters")
	ErrPostalCodeTooLong    = errors.New("postal code must not exceed 20 characters")
	ErrInvalidCountryCode   = errors.New("country code must be a valid 2-letter ISO 3166-1 alpha-2 code")

	// Onboarding lifecycle errors
	ErrInvalidOnboardingTransition = errors.New("invalid onboarding state transition")
	ErrProfileAlreadyDecided       = errors.New("profile onboarding decision is terminal")
)
