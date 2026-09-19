package domain

import (
	"fmt"
	"time"
)

var minDateOfBirth = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)

// DateOfBirth represents a customer's validated calendar date of birth.
// It enforces that the date is a valid Gregorian calendar date, is on or after
// 1900-01-01, and is not in the future relative to the evaluation date.
type DateOfBirth struct {
	year  int
	month time.Month
	day   int
}

// NewDateOfBirth constructs and validates a DateOfBirth from year, month, and day components.
func NewDateOfBirth(year int, month time.Month, day int, now time.Time) (DateOfBirth, error) {
	if month < time.January || month > time.December || day < 1 || day > 31 {
		return DateOfBirth{}, ErrInvalidDateOfBirth
	}

	// Go's time.Date normalizes overflow (e.g. Feb 30 -> Mar 2).
	// We verify that the reconstructed components match the input exactly.
	candidate := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	if candidate.Year() != year || candidate.Month() != month || candidate.Day() != day {
		return DateOfBirth{}, ErrInvalidDateOfBirth
	}

	if candidate.Before(minDateOfBirth) {
		return DateOfBirth{}, ErrDateOfBirthBefore1900
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}
	currentDate := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	if candidate.After(currentDate) {
		return DateOfBirth{}, ErrDateOfBirthInFuture
	}

	return DateOfBirth{
		year:  year,
		month: month,
		day:   day,
	}, nil
}

// ParseDateOfBirth parses an ISO-8601 date string ("YYYY-MM-DD") and validates it.
func ParseDateOfBirth(val string, now time.Time) (DateOfBirth, error) {
	parsed, err := time.Parse("2006-01-02", val)
	if err != nil {
		return DateOfBirth{}, ErrInvalidDateOfBirth
	}
	return NewDateOfBirth(parsed.Year(), parsed.Month(), parsed.Day(), now)
}

// Year returns the birth year.
func (d DateOfBirth) Year() int {
	return d.year
}

// Month returns the birth month.
func (d DateOfBirth) Month() time.Month {
	return d.month
}

// Day returns the birth day of the month.
func (d DateOfBirth) Day() int {
	return d.day
}

// Time returns midnight UTC on the date of birth.
func (d DateOfBirth) Time() time.Time {
	return time.Date(d.year, d.month, d.day, 0, 0, 0, 0, time.UTC)
}

// String returns the date in YYYY-MM-DD format.
func (d DateOfBirth) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.year, d.month, d.day)
}

// Age calculates the completed full years at the given reference time.
func (d DateOfBirth) Age(at time.Time) int {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	atUTC := at.UTC()
	age := atUTC.Year() - d.year
	if atUTC.Month() < d.month || (atUTC.Month() == d.month && atUTC.Day() < d.day) {
		age--
	}
	if age < 0 {
		return 0
	}
	return age
}

// IsAdult returns true if the age is 18 or older at the given reference time.
func (d DateOfBirth) IsAdult(at time.Time) bool {
	return d.Age(at) >= 18
}

// Equals checks value equality between two DateOfBirth instances.
func (d DateOfBirth) Equals(other DateOfBirth) bool {
	return d.year == other.year && d.month == other.month && d.day == other.day
}
