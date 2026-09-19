package domain

import (
	"strings"
	"unicode/utf8"
)

// LegalName represents a customer's verified legal name.
// It is an immutable value object enforcing length constraints between 1 and 100 characters
// for both given name and family name.
type LegalName struct {
	givenName  string
	familyName string
}

// NewLegalName creates and validates a new LegalName value object.
func NewLegalName(givenName, familyName string) (LegalName, error) {
	trimmedGiven := strings.TrimSpace(givenName)
	trimmedFamily := strings.TrimSpace(familyName)

	givenLen := utf8.RuneCountInString(trimmedGiven)
	if givenLen < 1 || givenLen > 100 {
		return LegalName{}, ErrInvalidGivenName
	}

	familyLen := utf8.RuneCountInString(trimmedFamily)
	if familyLen < 1 || familyLen > 100 {
		return LegalName{}, ErrInvalidFamilyName
	}

	return LegalName{
		givenName:  trimmedGiven,
		familyName: trimmedFamily,
	}, nil
}

// GivenName returns the customer's legal given name.
func (l LegalName) GivenName() string {
	return l.givenName
}

// FamilyName returns the customer's legal family name.
func (l LegalName) FamilyName() string {
	return l.familyName
}

// FullName returns the combined given and family name.
func (l LegalName) FullName() string {
	return l.givenName + " " + l.familyName
}

// String implements the fmt.Stringer interface.
func (l LegalName) String() string {
	return l.FullName()
}

// Equals checks value equality between two LegalName instances.
func (l LegalName) Equals(other LegalName) bool {
	return l.givenName == other.givenName && l.familyName == other.familyName
}

// IsZero returns true if the LegalName is an uninitialized zero value.
func (l LegalName) IsZero() bool {
	return l.givenName == "" && l.familyName == ""
}

