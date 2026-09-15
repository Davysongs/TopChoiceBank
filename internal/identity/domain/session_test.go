package domain

import (
	"testing"
	"time"
)

func TestSessionValidation(t *testing.T) {
	input := SessionInput{
		ID:               "s1",
		UserID:           "u1",
		RefreshFamilyID:  "rf1",
		AccessTokenJTI:   "at-jti",
		RefreshTokenHash: "rt-hash",
		IssuedAt:         time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC),
		ExpiresAt:        time.Date(2026, 9, 13, 10, 1, 0, 0, time.UTC),
		CreatedIP:        "127.0.0.1",
		UserAgent:        "test-agent",
	}
	s, err := NewSession(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.IsActive(time.Date(2026, 9, 13, 10, 0, 30, 0, time.UTC)) {
		t.Fatal("expected session active")
	}
	if s.Validate(time.Date(2026, 9, 13, 10, 2, 0, 0, time.UTC)) == nil {
		t.Fatal("expected session validation failure when expired")
	}
}
