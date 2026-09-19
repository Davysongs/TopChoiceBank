package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Davysongs/TopChoiceBank/internal/users/domain"
)

func TestNewLegalName_Valid(t *testing.T) {
	tests := []struct {
		name         string
		given        string
		family       string
		expectedFull string
	}{
		{
			name:         "standard ascii name",
			given:        "John",
			family:       "Doe",
			expectedFull: "John Doe",
		},
		{
			name:         "leading and trailing whitespace trimmed",
			given:        "  Jane  ",
			family:       "  Smith  ",
			expectedFull: "Jane Smith",
		},
		{
			name:         "single character boundaries",
			given:        "A",
			family:       "B",
			expectedFull: "A B",
		},
		{
			name:         "maximum length 100 runes each",
			given:        strings.Repeat("a", 100),
			family:       strings.Repeat("b", 100),
			expectedFull: strings.Repeat("a", 100) + " " + strings.Repeat("b", 100),
		},
		{
			name:         "unicode characters and hyphens",
			given:        "José-María",
			family:       "Nuñez-García",
			expectedFull: "José-María Nuñez-García",
		},
		{
			name:         "apostrophe in name",
			given:        "O'Connor",
			family:       "D'Angelo",
			expectedFull: "O'Connor D'Angelo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := domain.NewLegalName(tt.given, tt.family)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if ln.FullName() != tt.expectedFull {
				t.Errorf("expected FullName() = %q, got %q", tt.expectedFull, ln.FullName())
			}
			if ln.String() != tt.expectedFull {
				t.Errorf("expected String() = %q, got %q", tt.expectedFull, ln.String())
			}
			if ln.GivenName() != strings.TrimSpace(tt.given) {
				t.Errorf("expected GivenName() = %q, got %q", strings.TrimSpace(tt.given), ln.GivenName())
			}
			if ln.FamilyName() != strings.TrimSpace(tt.family) {
				t.Errorf("expected FamilyName() = %q, got %q", strings.TrimSpace(tt.family), ln.FamilyName())
			}
		})
	}
}

func TestNewLegalName_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		given       string
		family      string
		expectedErr error
	}{
		{
			name:        "empty given name",
			given:       "",
			family:      "Doe",
			expectedErr: domain.ErrInvalidGivenName,
		},
		{
			name:        "whitespace only given name",
			given:       "   \t\n  ",
			family:      "Doe",
			expectedErr: domain.ErrInvalidGivenName,
		},
		{
			name:        "given name exceeding 100 runes",
			given:       strings.Repeat("a", 101),
			family:      "Doe",
			expectedErr: domain.ErrInvalidGivenName,
		},
		{
			name:        "empty family name",
			given:       "John",
			family:      "",
			expectedErr: domain.ErrInvalidFamilyName,
		},
		{
			name:        "whitespace only family name",
			given:       "John",
			family:      "   ",
			expectedErr: domain.ErrInvalidFamilyName,
		},
		{
			name:        "family name exceeding 100 runes",
			given:       "John",
			family:      strings.Repeat("b", 101),
			expectedErr: domain.ErrInvalidFamilyName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := domain.NewLegalName(tt.given, tt.family)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.expectedErr)
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestLegalName_Equals(t *testing.T) {
	ln1, err := domain.NewLegalName("Alice", "Smith")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ln2, err := domain.NewLegalName("Alice", "Smith")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ln3, err := domain.NewLegalName("Bob", "Smith")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ln4, err := domain.NewLegalName("Alice", "Jones")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ln1.Equals(ln2) {
		t.Errorf("expected ln1 to equal ln2")
	}
	if ln1.Equals(ln3) {
		t.Errorf("expected ln1 not to equal ln3")
	}
	if ln1.Equals(ln4) {
		t.Errorf("expected ln1 not to equal ln4")
	}
}

