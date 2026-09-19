package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Davysongs/TopChoiceBank/internal/users/domain"
)

func TestNewAddress_Valid(t *testing.T) {
	tests := []struct {
		name              string
		line1             string
		line2             string
		city              string
		region            string
		postalCode        string
		countryCode       string
		expectedFormatted string
	}{
		{
			name:              "full US address",
			line1:             "123 Main St",
			line2:             "Apt 4B",
			city:              "New York",
			region:            "NY",
			postalCode:        "10001",
			countryCode:       "US",
			expectedFormatted: "123 Main St, Apt 4B, New York, NY, 10001, US",
		},
		{
			name:              "address with lowercase country code normalized",
			line1:             "10 Downing Street",
			line2:             "",
			city:              "London",
			region:            "Greater London",
			postalCode:        "SW1A 2AA",
			countryCode:       "gb",
			expectedFormatted: "10 Downing Street, London, Greater London, SW1A 2AA, GB",
		},
		{
			name:              "minimal address without optional fields",
			line1:             "Plot 12 Commercial Ave",
			line2:             "",
			city:              "Lagos",
			region:            "",
			postalCode:        "",
			countryCode:       "NG",
			expectedFormatted: "Plot 12 Commercial Ave, Lagos, NG",
		},
		{
			name:              "Germany address with whitespace trimming",
			line1:             "  Unter den Linden 1  ",
			line2:             "  ",
			city:              "  Berlin  ",
			region:            "",
			postalCode:        "  10117  ",
			countryCode:       "  DE  ",
			expectedFormatted: "Unter den Linden 1, Berlin, 10117, DE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := domain.NewAddress(tt.line1, tt.line2, tt.city, tt.region, tt.postalCode, tt.countryCode)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if addr.Formatted() != tt.expectedFormatted {
				t.Errorf("expected Formatted() = %q, got %q", tt.expectedFormatted, addr.Formatted())
			}
			if addr.Line1() != strings.TrimSpace(tt.line1) {
				t.Errorf("expected Line1() = %q, got %q", strings.TrimSpace(tt.line1), addr.Line1())
			}
			if addr.City() != strings.TrimSpace(tt.city) {
				t.Errorf("expected City() = %q, got %q", strings.TrimSpace(tt.city), addr.City())
			}
			if addr.CountryCode() != strings.ToUpper(strings.TrimSpace(tt.countryCode)) {
				t.Errorf("expected CountryCode() = %q, got %q", strings.ToUpper(strings.TrimSpace(tt.countryCode)), addr.CountryCode())
			}
		})
	}
}

func TestNewAddress_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		line1       string
		line2       string
		city        string
		region      string
		postalCode  string
		countryCode string
		expectedErr error
	}{
		{
			name:        "empty line1",
			line1:       "",
			city:        "New York",
			countryCode: "US",
			expectedErr: domain.ErrEmptyAddressLine1,
		},
		{
			name:        "whitespace line1",
			line1:       "   \t  ",
			city:        "New York",
			countryCode: "US",
			expectedErr: domain.ErrEmptyAddressLine1,
		},
		{
			name:        "line1 too long",
			line1:       strings.Repeat("a", 256),
			city:        "New York",
			countryCode: "US",
			expectedErr: domain.ErrAddressLine1TooLong,
		},
		{
			name:        "line2 too long",
			line1:       "123 Main St",
			line2:       strings.Repeat("b", 256),
			city:        "New York",
			countryCode: "US",
			expectedErr: domain.ErrAddressLine2TooLong,
		},
		{
			name:        "empty city",
			line1:       "123 Main St",
			city:        "",
			countryCode: "US",
			expectedErr: domain.ErrEmptyCity,
		},
		{
			name:        "city too long",
			line1:       "123 Main St",
			city:        strings.Repeat("c", 101),
			countryCode: "US",
			expectedErr: domain.ErrCityTooLong,
		},
		{
			name:        "region too long",
			line1:       "123 Main St",
			city:        "New York",
			region:      strings.Repeat("r", 101),
			countryCode: "US",
			expectedErr: domain.ErrRegionTooLong,
		},
		{
			name:        "postal code too long",
			line1:       "123 Main St",
			city:        "New York",
			postalCode:  strings.Repeat("1", 21),
			countryCode: "US",
			expectedErr: domain.ErrPostalCodeTooLong,
		},
		{
			name:        "empty country code",
			line1:       "123 Main St",
			city:        "New York",
			countryCode: "",
			expectedErr: domain.ErrInvalidCountryCode,
		},
		{
			name:        "non-existent 2-letter country code ZZ",
			line1:       "123 Main St",
			city:        "New York",
			countryCode: "ZZ",
			expectedErr: domain.ErrInvalidCountryCode,
		},
		{
			name:        "3-letter country code USA",
			line1:       "123 Main St",
			city:        "New York",
			countryCode: "USA",
			expectedErr: domain.ErrInvalidCountryCode,
		},
		{
			name:        "numeric country code",
			line1:       "123 Main St",
			city:        "New York",
			countryCode: "12",
			expectedErr: domain.ErrInvalidCountryCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := domain.NewAddress(tt.line1, tt.line2, tt.city, tt.region, tt.postalCode, tt.countryCode)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.expectedErr)
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestAddress_Equals(t *testing.T) {
	a1, _ := domain.NewAddress("123 Main St", "Apt 1", "City", "Reg", "12345", "US")
	a2, _ := domain.NewAddress("123 Main St", "Apt 1", "City", "Reg", "12345", "US")
	a3, _ := domain.NewAddress("123 Main St", "Apt 2", "City", "Reg", "12345", "US")

	if !a1.Equals(a2) {
		t.Errorf("expected a1 to equal a2")
	}
	if a1.Equals(a3) {
		t.Errorf("expected a1 not to equal a3")
	}
}

