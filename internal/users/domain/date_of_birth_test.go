package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/users/domain"
)

func TestNewDateOfBirth_Valid(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		year        int
		month       time.Month
		day         int
		expectedStr string
	}{
		{
			name:        "earliest allowed date",
			year:        1900,
			month:       time.January,
			day:         1,
			expectedStr: "1900-01-01",
		},
		{
			name:        "standard birth date",
			year:        1995,
			month:       time.June,
			day:         15,
			expectedStr: "1995-06-15",
		},
		{
			name:        "leap year date (2000)",
			year:        2000,
			month:       time.February,
			day:         29,
			expectedStr: "2000-02-29",
		},
		{
			name:        "leap year date (2004)",
			year:        2004,
			month:       time.February,
			day:         29,
			expectedStr: "2004-02-29",
		},
		{
			name:        "born today",
			year:        2026,
			month:       time.September,
			day:         19,
			expectedStr: "2026-09-19",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dob, err := domain.NewDateOfBirth(tt.year, tt.month, tt.day, now)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if dob.String() != tt.expectedStr {
				t.Errorf("expected String() = %q, got %q", tt.expectedStr, dob.String())
			}
			if dob.Year() != tt.year {
				t.Errorf("expected Year() = %d, got %d", tt.year, dob.Year())
			}
			if dob.Month() != tt.month {
				t.Errorf("expected Month() = %v, got %v", tt.month, dob.Month())
			}
			if dob.Day() != tt.day {
				t.Errorf("expected Day() = %d, got %d", tt.day, dob.Day())
			}
			expectedTime := time.Date(tt.year, tt.month, tt.day, 0, 0, 0, 0, time.UTC)
			if !dob.Time().Equal(expectedTime) {
				t.Errorf("expected Time() = %v, got %v", expectedTime, dob.Time())
			}
		})
	}
}

func TestNewDateOfBirth_Invalid(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		year        int
		month       time.Month
		day         int
		expectedErr error
	}{
		{
			name:        "before 1900",
			year:        1899,
			month:       time.December,
			day:         31,
			expectedErr: domain.ErrDateOfBirthBefore1900,
		},
		{
			name:        "in the future (tomorrow)",
			year:        2026,
			month:       time.September,
			day:         20,
			expectedErr: domain.ErrDateOfBirthInFuture,
		},
		{
			name:        "non-leap year Feb 29 (1900)",
			year:        1900,
			month:       time.February,
			day:         29,
			expectedErr: domain.ErrInvalidDateOfBirth,
		},
		{
			name:        "non-leap year Feb 29 (2001)",
			year:        2001,
			month:       time.February,
			day:         29,
			expectedErr: domain.ErrInvalidDateOfBirth,
		},
		{
			name:        "invalid day 31 in April",
			year:        2000,
			month:       time.April,
			day:         31,
			expectedErr: domain.ErrInvalidDateOfBirth,
		},
		{
			name:        "day 0",
			year:        2000,
			month:       time.May,
			day:         0,
			expectedErr: domain.ErrInvalidDateOfBirth,
		},
		{
			name:        "day 32",
			year:        2000,
			month:       time.May,
			day:         32,
			expectedErr: domain.ErrInvalidDateOfBirth,
		},
		{
			name:        "month 0",
			year:        2000,
			month:       0,
			day:         15,
			expectedErr: domain.ErrInvalidDateOfBirth,
		},
		{
			name:        "month 13",
			year:        2000,
			month:       13,
			day:         15,
			expectedErr: domain.ErrInvalidDateOfBirth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := domain.NewDateOfBirth(tt.year, tt.month, tt.day, now)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.expectedErr)
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestParseDateOfBirth(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)

	t.Run("valid parse", func(t *testing.T) {
		dob, err := domain.ParseDateOfBirth("1992-08-24", now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dob.String() != "1992-08-24" {
			t.Errorf("expected '1992-08-24', got %q", dob.String())
		}
	})

	t.Run("malformed formats", func(t *testing.T) {
		malformed := []string{
			"1992/08/24",
			"24-08-1992",
			"1992-8-24",
			"not-a-date",
			"",
		}
		for _, s := range malformed {
			_, err := domain.ParseDateOfBirth(s, now)
			if err == nil {
				t.Errorf("expected error for input %q, got nil", s)
			}
			if !errors.Is(err, domain.ErrInvalidDateOfBirth) {
				t.Errorf("expected ErrInvalidDateOfBirth for %q, got: %v", s, err)
			}
		}
	})
}

func TestDateOfBirth_AgeAndIsAdult(t *testing.T) {
	dob, err := domain.NewDateOfBirth(2000, time.September, 19, time.Date(2000, time.September, 19, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1 day before 18th birthday: 2018-09-18
	refBefore18 := time.Date(2018, time.September, 18, 23, 59, 59, 0, time.UTC)
	if age := dob.Age(refBefore18); age != 17 {
		t.Errorf("expected age 17, got %d", age)
	}
	if dob.IsAdult(refBefore18) {
		t.Errorf("expected IsAdult to be false before 18th birthday")
	}

	// On 18th birthday: 2018-09-19
	refOn18 := time.Date(2018, time.September, 19, 0, 0, 0, 0, time.UTC)
	if age := dob.Age(refOn18); age != 18 {
		t.Errorf("expected age 18, got %d", age)
	}
	if !dob.IsAdult(refOn18) {
		t.Errorf("expected IsAdult to be true on 18th birthday")
	}

	// 1 day after 18th birthday: 2018-09-20
	refAfter18 := time.Date(2018, time.September, 20, 0, 0, 0, 0, time.UTC)
	if age := dob.Age(refAfter18); age != 18 {
		t.Errorf("expected age 18, got %d", age)
	}
	if !dob.IsAdult(refAfter18) {
		t.Errorf("expected IsAdult to be true after 18th birthday")
	}
}

func TestDateOfBirth_Equals(t *testing.T) {
	now := time.Date(2026, time.September, 19, 0, 0, 0, 0, time.UTC)
	d1, _ := domain.NewDateOfBirth(1990, time.March, 10, now)
	d2, _ := domain.NewDateOfBirth(1990, time.March, 10, now)
	d3, _ := domain.NewDateOfBirth(1990, time.March, 11, now)
	d4, _ := domain.NewDateOfBirth(1991, time.March, 10, now)

	if !d1.Equals(d2) {
		t.Errorf("expected d1 to equal d2")
	}
	if d1.Equals(d3) {
		t.Errorf("expected d1 not to equal d3")
	}
	if d1.Equals(d4) {
		t.Errorf("expected d1 not to equal d4")
	}
}
