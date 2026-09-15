package domain

import (
	"testing"
	"time"
)

func TestSessionAggregateRotate(t *testing.T) {
	family, err := NewRefreshFamily("rf1", "u1", time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	session, err := NewSession(SessionInput{
		ID:               "s1",
		UserID:           "u1",
		RefreshFamilyID:  "rf1",
		AccessTokenJTI:   "at-jti-1",
		RefreshTokenHash: "rt-hash-1",
		IssuedAt:         time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC),
		ExpiresAt:        time.Date(2026, 9, 13, 10, 30, 0, 0, time.UTC),
		CreatedIP:        "127.0.0.1",
		UserAgent:        "test-agent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	agg, err := NewSessionAggregate(family, session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	next, err := agg.Rotate(time.Date(2026, 9, 13, 10, 5, 0, 0, time.UTC), SessionInput{
		ID:               "s2",
		UserID:           "u1",
		RefreshFamilyID:  "rf1",
		AccessTokenJTI:   "at-jti-2",
		RefreshTokenHash: "rt-hash-2",
		ExpiresAt:        time.Date(2026, 9, 13, 10, 35, 0, 0, time.UTC),
		CreatedIP:        "127.0.0.1",
		UserAgent:        "test-agent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next == nil || next.RotatedFromSessionID == nil || *next.RotatedFromSessionID != "s1" {
		t.Fatal("expected rotated session to reference source session")
	}
	if session.RevokedAt == nil {
		t.Fatal("expected source session to be revoked on rotate")
	}
}

func TestSessionAggregateRotateFailsForRevokedFamily(t *testing.T) {
	family, err := NewRefreshFamily("rf2", "u1", time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	family.Revoke("manual", time.Date(2026, 9, 13, 9, 30, 0, 0, time.UTC))

	session, err := NewSession(SessionInput{
		ID:               "s3",
		UserID:           "u1",
		RefreshFamilyID:  "rf2",
		AccessTokenJTI:   "at-jti-3",
		RefreshTokenHash: "rt-hash-3",
		IssuedAt:         time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC),
		ExpiresAt:        time.Date(2026, 9, 13, 10, 30, 0, 0, time.UTC),
		CreatedIP:        "127.0.0.1",
		UserAgent:        "test-agent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	agg, err := NewSessionAggregate(family, session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = agg.Rotate(time.Date(2026, 9, 13, 10, 1, 0, 0, time.UTC), SessionInput{
		ID:               "s4",
		UserID:           "u1",
		RefreshFamilyID:  "rf2",
		AccessTokenJTI:   "at-jti-4",
		RefreshTokenHash: "rt-hash-4",
		ExpiresAt:        time.Date(2026, 9, 13, 10, 35, 0, 0, time.UTC),
		CreatedIP:        "127.0.0.1",
		UserAgent:        "test-agent",
	})
	if err == nil {
		t.Fatal("expected rotation failure for revoked family")
	}
}

func TestNewSessionAggregateFamilyMismatch(t *testing.T) {
	family, err := NewRefreshFamily("rf1", "u1", time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	session, err := NewSession(SessionInput{
		ID:               "s1",
		UserID:           "u1",
		RefreshFamilyID:  "rf2", // Mismatched family ID
		AccessTokenJTI:   "at-jti-1",
		RefreshTokenHash: "rt-hash-1",
		IssuedAt:         time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC),
		ExpiresAt:        time.Date(2026, 9, 13, 10, 30, 0, 0, time.UTC),
		CreatedIP:        "127.0.0.1",
		UserAgent:        "test-agent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = NewSessionAggregate(family, session)
	if err != ErrAggregateMismatch {
		t.Fatalf("expected ErrAggregateMismatch, got %v", err)
	}
}

func TestSessionAggregateRotateWithZeroNow(t *testing.T) {
	family, err := NewRefreshFamily("rf1", "u1", time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	session, err := NewSession(SessionInput{
		ID:               "s1",
		UserID:           "u1",
		RefreshFamilyID:  "rf1",
		AccessTokenJTI:   "at-jti-1",
		RefreshTokenHash: "rt-hash-1",
		IssuedAt:         time.Now().UTC(),
		ExpiresAt:        time.Now().UTC().Add(1 * time.Hour),
		CreatedIP:        "127.0.0.1",
		UserAgent:        "test-agent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	agg, err := NewSessionAggregate(family, session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rotated, err := agg.Rotate(time.Time{}, SessionInput{
		ID:               "s2",
		UserID:           "u1",
		RefreshFamilyID:  "rf1",
		AccessTokenJTI:   "at-jti-2",
		RefreshTokenHash: "rt-hash-2",
		ExpiresAt:        time.Now().UTC().Add(2 * time.Hour),
		CreatedIP:        "127.0.0.1",
		UserAgent:        "test-agent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rotated.IssuedAt.IsZero() {
		t.Fatal("expected rotated session IssuedAt to be normalized and non-zero")
	}
	if agg.Family.LastUsedAt == nil || agg.Family.LastUsedAt.IsZero() {
		t.Fatal("expected family LastUsedAt to be normalized and non-zero")
	}
	if agg.Family.UpdatedAt.IsZero() {
		t.Fatal("expected family UpdatedAt to be normalized and non-zero")
	}
	if session.RevokedAt == nil || session.RevokedAt.IsZero() {
		t.Fatal("expected source session RevokedAt to be normalized and non-zero")
	}

	if !rotated.IssuedAt.Equal(*agg.Family.LastUsedAt) || !rotated.IssuedAt.Equal(agg.Family.UpdatedAt) || !rotated.IssuedAt.Equal(*session.RevokedAt) {
		t.Fatal("expected normalized timestamps to be equal across rotation operations")
	}
}
