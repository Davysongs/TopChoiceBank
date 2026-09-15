package domain

import (
	"testing"
	"time"
)

func TestNewUserRejectsInvalidInput(t *testing.T) {
	if _, err := NewUser("", "test@example.com", "hash", time.Now()); err == nil {
		t.Fatal("expected invalid identifier")
	}
	if _, err := NewUser("u1", "", "hash", time.Now()); err == nil {
		t.Fatal("expected invalid email")
	}
	if _, err := NewUser("u1", "test@example.com", "", time.Now()); err == nil {
		t.Fatal("expected invalid password hash")
	}
}

func TestUserLockoutWindowResetsAndLocks(t *testing.T) {
	clock := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	user, err := NewUser("u1", "test@example.com", "hash", clock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := 0; i < 4; i++ {
		user.RecordFailedLogin(clock, 15*time.Minute, 30*time.Minute, 5)
	}
	if user.IsLocked(clock) {
		t.Fatal("expected not locked before threshold")
	}

	user.RecordFailedLogin(clock, 15*time.Minute, 30*time.Minute, 5)
	if !user.IsLocked(clock) {
		t.Fatal("expected account to be locked")
	}
}

func TestUserLockoutPreservesPriorStatus(t *testing.T) {
	clock := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	// Pending status preservation
	userPending, err := NewUser("u1", "pending@example.com", "hash", clock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userPending.Status != UserStatusPending {
		t.Fatalf("expected initial status UserStatusPending, got %s", userPending.Status)
	}
	for i := 0; i < 5; i++ {
		userPending.RecordFailedLogin(clock, 15*time.Minute, 30*time.Minute, 5)
	}
	if userPending.Status != UserStatusLocked {
		t.Fatalf("expected status UserStatusLocked, got %s", userPending.Status)
	}

	// Expire lockout for pending user
	futureClock := clock.Add(31 * time.Minute)
	userPending.RecordFailedLogin(futureClock, 15*time.Minute, 30*time.Minute, 5)
	if userPending.Status != UserStatusPending {
		t.Fatalf("expected status restored to UserStatusPending, got %s", userPending.Status)
	}

	// Disabled status preservation
	userDisabled, err := NewUser("u2", "disabled@example.com", "hash", clock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	userDisabled.Status = UserStatusDisabled

	for i := 0; i < 5; i++ {
		userDisabled.RecordFailedLogin(clock, 15*time.Minute, 30*time.Minute, 5)
	}
	if userDisabled.Status != UserStatusLocked {
		t.Fatalf("expected status UserStatusLocked, got %s", userDisabled.Status)
	}

	// Expire lockout for disabled user
	userDisabled.RecordFailedLogin(futureClock, 15*time.Minute, 30*time.Minute, 5)
	if userDisabled.Status != UserStatusDisabled {
		t.Fatalf("expected status restored to UserStatusDisabled, got %s", userDisabled.Status)
	}
}
