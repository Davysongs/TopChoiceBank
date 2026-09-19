package domain

import (
	"regexp"
	"strings"
)

// e164Regex strictly enforces ITU-T E.164 phone numbering plan:
// Begins with '+', country calling code starting with [1-9], total 8 to 15 digits.
var e164Regex = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

// Phone represents a validated ITU-T E.164 international phone number.
type Phone struct {
	value string
}

// NewPhone constructs and strictly validates an E.164 phone number.
func NewPhone(raw string) (Phone, error) {
	trimmed := strings.TrimSpace(raw)
	if !e164Regex.MatchString(trimmed) {
		return Phone{}, ErrInvalidPhoneNumber
	}

	return Phone{
		value: trimmed,
	}, nil
}

// Value returns the raw E.164 string (e.g. "+12025550143").
func (p Phone) Value() string {
	return p.value
}

// String implements the fmt.Stringer interface.
func (p Phone) String() string {
	return p.value
}

// Masked returns a masked representation suitable for display and logging without PII leakage,
// preserving the '+' and prefix plus the final 4 digits (e.g. "+1*****0143").
func (p Phone) Masked() string {
	if len(p.value) < 7 {
		return p.value
	}
	// Prefix: first 2 chars (e.g. "+1" or "+4")
	prefix := p.value[:2]
	suffix := p.value[len(p.value)-4:]
	maskLen := len(p.value) - len(prefix) - len(suffix)
	if maskLen < 1 {
		maskLen = 1
	}
	return prefix + strings.Repeat("*", maskLen) + suffix
}

// Equals checks value equality between two Phone instances.
func (p Phone) Equals(other Phone) bool {
	return p.value == other.value
}

