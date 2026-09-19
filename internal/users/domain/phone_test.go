package domain_test

import (
	"errors"
	"testing"

	"github.com/Davysongs/TopChoiceBank/internal/users/domain"
)

func TestNewPhone_Valid(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		expectedValue  string
		expectedMasked string
	}{
		{
			name:           "US number",
			raw:            "+12025550143",
			expectedValue:  "+12025550143",
			expectedMasked: "+1******0143",
		},
		{
			name:           "UK number",
			raw:            "+447911123456",
			expectedValue:  "+447911123456",
			expectedMasked: "+4*******3456",
		},
		{
			name:           "Nigeria number",
			raw:            "+2348031234567",
			expectedValue:  "+2348031234567",
			expectedMasked: "+2********4567",
		},
		{
			name:           "minimum digits (8 digits after +)",
			raw:            "+12345678",
			expectedValue:  "+12345678",
			expectedMasked: "+1***5678",
		},
		{
			name:           "maximum digits (15 digits after +)",
			raw:            "+123456789012345",
			expectedValue:  "+123456789012345",
			expectedMasked: "+1**********2345",
		},
		{
			name:           "whitespace trimmed",
			raw:            "  +12025550143  ",
			expectedValue:  "+12025550143",
			expectedMasked: "+1******0143",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			phone, err := domain.NewPhone(tt.raw)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if phone.Value() != tt.expectedValue {
				t.Errorf("expected Value() = %q, got %q", tt.expectedValue, phone.Value())
			}
			if phone.String() != tt.expectedValue {
				t.Errorf("expected String() = %q, got %q", tt.expectedValue, phone.String())
			}
			if phone.Masked() != tt.expectedMasked {
				t.Errorf("expected Masked() = %q, got %q", tt.expectedMasked, phone.Masked())
			}
		})
	}
}

func TestNewPhone_Invalid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty string", raw: ""},
		{name: "whitespace only", raw: "   "},
		{name: "missing plus sign", raw: "12025550143"},
		{name: "leading zero after plus", raw: "+012025550143"},
		{name: "contains spaces", raw: "+1 202 555 0143"},
		{name: "contains hyphens", raw: "+1-202-555-0143"},
		{name: "contains parentheses", raw: "+1(202)5550143"},
		{name: "letters in number", raw: "+1800FLOWERS"},
		{name: "special characters", raw: "+1202555014#"},
		{name: "too short (7 digits after +)", raw: "+1234567"},
		{name: "too long (16 digits after +)", raw: "+1234567890123456"},
		{name: "plus sign only", raw: "+"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := domain.NewPhone(tt.raw)
			if err == nil {
				t.Fatalf("expected error for input %q, got nil", tt.raw)
			}
			if !errors.Is(err, domain.ErrInvalidPhoneNumber) {
				t.Errorf("expected ErrInvalidPhoneNumber, got %v", err)
			}
		})
	}
}

func TestPhone_Equals(t *testing.T) {
	p1, _ := domain.NewPhone("+12025550143")
	p2, _ := domain.NewPhone("+12025550143")
	p3, _ := domain.NewPhone("+447911123456")

	if !p1.Equals(p2) {
		t.Errorf("expected p1 to equal p2")
	}
	if p1.Equals(p3) {
		t.Errorf("expected p1 not to equal p3")
	}
}
