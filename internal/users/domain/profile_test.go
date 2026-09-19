package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/users/domain"
)

func createTestFixtures(t *testing.T) (domain.LegalName, domain.DateOfBirth, domain.Phone, domain.Address) {
	t.Helper()
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)

	name, err := domain.NewLegalName("Alice", "Smith")
	if err != nil {
		t.Fatalf("failed to create LegalName: %v", err)
	}

	dob, err := domain.NewDateOfBirth(1995, time.June, 15, now)
	if err != nil {
		t.Fatalf("failed to create DateOfBirth: %v", err)
	}

	phone, err := domain.NewPhone("+12025550143")
	if err != nil {
		t.Fatalf("failed to create Phone: %v", err)
	}

	addr, err := domain.NewAddress("123 Financial Way", "Suite 100", "New York", "NY", "10001", "US")
	if err != nil {
		t.Fatalf("failed to create Address: %v", err)
	}

	return name, dob, phone, addr
}

func TestNewProfile_Valid(t *testing.T) {
	name, dob, phone, addr := createTestFixtures(t)
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)

	profile, err := domain.NewProfile("user-uuid-1234", name, dob, phone, addr, now)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if profile.UserID() != "user-uuid-1234" {
		t.Errorf("expected UserID 'user-uuid-1234', got %q", profile.UserID())
	}
	if !profile.LegalName().Equals(name) {
		t.Errorf("expected LegalName %v, got %v", name, profile.LegalName())
	}
	if !profile.DateOfBirth().Equals(dob) {
		t.Errorf("expected DateOfBirth %v, got %v", dob, profile.DateOfBirth())
	}
	if !profile.Phone().Equals(phone) {
		t.Errorf("expected Phone %v, got %v", phone, profile.Phone())
	}
	if !profile.Address().Equals(addr) {
		t.Errorf("expected Address %v, got %v", addr, profile.Address())
	}
	if profile.OnboardingState() != domain.OnboardingStatePending {
		t.Errorf("expected state PENDING, got %q", profile.OnboardingState())
	}
	if profile.OnboardingSubmittedAt() != nil {
		t.Errorf("expected nil OnboardingSubmittedAt, got %v", profile.OnboardingSubmittedAt())
	}
	if profile.OnboardingDecidedAt() != nil {
		t.Errorf("expected nil OnboardingDecidedAt, got %v", profile.OnboardingDecidedAt())
	}
	if profile.Version() != 1 {
		t.Errorf("expected Version 1, got %d", profile.Version())
	}
	if !profile.CreatedAt().Equal(now) {
		t.Errorf("expected CreatedAt %v, got %v", now, profile.CreatedAt())
	}
	if !profile.UpdatedAt().Equal(now) {
		t.Errorf("expected UpdatedAt %v, got %v", now, profile.UpdatedAt())
	}
}

func TestNewProfile_EmptyUserID(t *testing.T) {
	name, dob, phone, addr := createTestFixtures(t)
	now := time.Now().UTC()

	tests := []string{"", "   ", "\t\n"}
	for _, id := range tests {
		_, err := domain.NewProfile(id, name, dob, phone, addr, now)
		if err == nil {
			t.Fatalf("expected error for empty userID %q, got nil", id)
		}
		if !errors.Is(err, domain.ErrEmptyUserID) {
			t.Errorf("expected ErrEmptyUserID, got %v", err)
		}
	}
}

func TestReconstituteProfile(t *testing.T) {
	name, dob, phone, addr := createTestFixtures(t)
	now := time.Now().UTC()
	subTime := now.Add(-1 * time.Hour)
	decTime := now

	t.Run("valid reconstitution with decision", func(t *testing.T) {
		p, err := domain.ReconstituteProfile(
			"user-uuid-1234",
			name,
			dob,
			phone,
			addr,
			domain.OnboardingStateApproved,
			&subTime,
			&decTime,
			3,
			now.Add(-24*time.Hour),
			now,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.OnboardingState() != domain.OnboardingStateApproved {
			t.Errorf("expected state APPROVED, got %v", p.OnboardingState())
		}
		if p.Version() != 3 {
			t.Errorf("expected version 3, got %d", p.Version())
		}
	})

	t.Run("invalid reconstitution: empty onboarding state", func(t *testing.T) {
		_, err := domain.ReconstituteProfile(
			"user-uuid-1234",
			name,
			dob,
			phone,
			addr,
			"",
			&subTime,
			&decTime,
			1,
			now,
			now,
		)
		if err == nil {
			t.Fatal("expected error for empty onboarding state, got nil")
		}
		if !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition, got %v", err)
		}
	})

	t.Run("invalid reconstitution: unknown onboarding state", func(t *testing.T) {
		_, err := domain.ReconstituteProfile(
			"user-uuid-1234",
			name,
			dob,
			phone,
			addr,
			"UNKNOWN_STATE",
			&subTime,
			&decTime,
			1,
			now,
			now,
		)
		if err == nil {
			t.Fatal("expected error for unknown onboarding state, got nil")
		}
		if !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition, got %v", err)
		}
	})

	t.Run("invalid reconstitution: approved state without decidedAt", func(t *testing.T) {
		_, err := domain.ReconstituteProfile(
			"user-uuid-1234",
			name,
			dob,
			phone,
			addr,
			domain.OnboardingStateApproved,
			&subTime,
			nil,
			1,
			now,
			now,
		)
		if err == nil {
			t.Fatal("expected error for approved state without decidedAt, got nil")
		}
		if !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition, got %v", err)
		}
	})

	t.Run("invalid reconstitution: rejected state without decidedAt", func(t *testing.T) {
		_, err := domain.ReconstituteProfile(
			"user-uuid-1234",
			name,
			dob,
			phone,
			addr,
			domain.OnboardingStateRejected,
			&subTime,
			nil,
			1,
			now,
			now,
		)
		if err == nil {
			t.Fatal("expected error for rejected state without decidedAt, got nil")
		}
		if !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition, got %v", err)
		}
	})

	t.Run("invalid reconstitution: decided without being submitted", func(t *testing.T) {
		_, err := domain.ReconstituteProfile(
			"user-uuid-1234",
			name,
			dob,
			phone,
			addr,
			domain.OnboardingStateApproved,
			nil,
			&decTime,
			1,
			now,
			now,
		)
		if err == nil {
			t.Fatal("expected error for decidedAt without submittedAt, got nil")
		}
		if !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition, got %v", err)
		}
	})

	t.Run("valid reconstitution with pending state", func(t *testing.T) {
		p, err := domain.ReconstituteProfile(
			"user-uuid-1234",
			name,
			dob,
			phone,
			addr,
			domain.OnboardingStatePending,
			nil,
			nil,
			1,
			now,
			now,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.OnboardingState() != domain.OnboardingStatePending {
			t.Errorf("expected state PENDING, got %v", p.OnboardingState())
		}
	})

	t.Run("valid reconstitution with rejected state and decision", func(t *testing.T) {
		p, err := domain.ReconstituteProfile(
			"user-uuid-1234",
			name,
			dob,
			phone,
			addr,
			domain.OnboardingStateRejected,
			&subTime,
			&decTime,
			2,
			now.Add(-24*time.Hour),
			now,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.OnboardingState() != domain.OnboardingStateRejected {
			t.Errorf("expected state REJECTED, got %v", p.OnboardingState())
		}
	})
}

func TestProfile_OnboardingStateMachine(t *testing.T) {
	name, dob, phone, addr := createTestFixtures(t)
	t0 := time.Date(2026, time.September, 19, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Hour)
	t2 := t0.Add(2 * time.Hour)

	t.Run("happy path: PENDING -> UNDER_REVIEW -> APPROVED", func(t *testing.T) {
		p, _ := domain.NewProfile("user-1", name, dob, phone, addr, t0)

		// Cannot approve or reject while PENDING
		if err := p.ApproveOnboarding(t1); !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition when approving from PENDING, got %v", err)
		}
		if err := p.RejectOnboarding(t1); !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition when rejecting from PENDING, got %v", err)
		}

		// Submit for review
		if err := p.SubmitOnboarding(t1); err != nil {
			t.Fatalf("unexpected error on SubmitOnboarding: %v", err)
		}
		if p.OnboardingState() != domain.OnboardingStateUnderReview {
			t.Errorf("expected state UNDER_REVIEW, got %v", p.OnboardingState())
		}
		if p.OnboardingSubmittedAt() == nil || !p.OnboardingSubmittedAt().Equal(t1) {
			t.Errorf("expected submittedAt %v, got %v", t1, p.OnboardingSubmittedAt())
		}
		if p.Version() != 2 {
			t.Errorf("expected version 2, got %d", p.Version())
		}

		// Cannot submit again while already UNDER_REVIEW
		if err := p.SubmitOnboarding(t1); !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition on redundant submit, got %v", err)
		}

		// Approve
		if err := p.ApproveOnboarding(t2); err != nil {
			t.Fatalf("unexpected error on ApproveOnboarding: %v", err)
		}
		if p.OnboardingState() != domain.OnboardingStateApproved {
			t.Errorf("expected state APPROVED, got %v", p.OnboardingState())
		}
		if p.OnboardingDecidedAt() == nil || !p.OnboardingDecidedAt().Equal(t2) {
			t.Errorf("expected decidedAt %v, got %v", t2, p.OnboardingDecidedAt())
		}
		if p.Version() != 3 {
			t.Errorf("expected version 3, got %d", p.Version())
		}

		// Terminal: cannot submit, approve, or reject after APPROVED
		if err := p.SubmitOnboarding(t2); !errors.Is(err, domain.ErrProfileAlreadyDecided) {
			t.Errorf("expected ErrProfileAlreadyDecided on submit after approval, got %v", err)
		}
		if err := p.ApproveOnboarding(t2); !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition on approve after approval, got %v", err)
		}
		if err := p.RejectOnboarding(t2); !errors.Is(err, domain.ErrInvalidOnboardingTransition) {
			t.Errorf("expected ErrInvalidOnboardingTransition on reject after approval, got %v", err)
		}
	})

	t.Run("rejection and resubmission: PENDING -> UNDER_REVIEW -> REJECTED -> UNDER_REVIEW", func(t *testing.T) {
		p, _ := domain.NewProfile("user-2", name, dob, phone, addr, t0)

		if err := p.SubmitOnboarding(t1); err != nil {
			t.Fatalf("unexpected error on submit: %v", err)
		}

		// Reject
		if err := p.RejectOnboarding(t2); err != nil {
			t.Fatalf("unexpected error on reject: %v", err)
		}
		if p.OnboardingState() != domain.OnboardingStateRejected {
			t.Errorf("expected state REJECTED, got %v", p.OnboardingState())
		}
		if p.OnboardingDecidedAt() == nil || !p.OnboardingDecidedAt().Equal(t2) {
			t.Errorf("expected decidedAt %v, got %v", t2, p.OnboardingDecidedAt())
		}

		// Resubmit from REJECTED
		t3 := t2.Add(24 * time.Hour)
		if err := p.SubmitOnboarding(t3); err != nil {
			t.Fatalf("unexpected error on resubmit from REJECTED: %v", err)
		}
		if p.OnboardingState() != domain.OnboardingStateUnderReview {
			t.Errorf("expected state UNDER_REVIEW after resubmit, got %v", p.OnboardingState())
		}
		if p.OnboardingDecidedAt() != nil {
			t.Errorf("expected decidedAt to be cleared upon resubmit, got %v", p.OnboardingDecidedAt())
		}
		if p.OnboardingSubmittedAt() == nil || !p.OnboardingSubmittedAt().Equal(t3) {
			t.Errorf("expected submittedAt %v, got %v", t3, p.OnboardingSubmittedAt())
		}
	})
}

func TestProfile_ContactUpdates(t *testing.T) {
	name, dob, phone, addr := createTestFixtures(t)
	t0 := time.Date(2026, time.September, 19, 10, 0, 0, 0, time.UTC)
	profile, _ := domain.NewProfile("user-1", name, dob, phone, addr, t0)

	newPhone, err := domain.NewPhone("+447911123456")
	if err != nil {
		t.Fatalf("failed to create new phone: %v", err)
	}

	newAddr, err := domain.NewAddress("221B Baker St", "", "London", "", "NW1 6XE", "GB")
	if err != nil {
		t.Fatalf("failed to create new address: %v", err)
	}

	t1 := t0.Add(1 * time.Hour)

	t.Run("UpdateContact updates both and bumps version", func(t *testing.T) {
		if err := profile.UpdateContact(newPhone, newAddr, t1); err != nil {
			t.Fatalf("unexpected error updating contact: %v", err)
		}

		if !profile.Phone().Equals(newPhone) {
			t.Errorf("expected phone %v, got %v", newPhone, profile.Phone())
		}
		if !profile.Address().Equals(newAddr) {
			t.Errorf("expected address %v, got %v", newAddr, profile.Address())
		}
		// Legal identity must remain intact
		if !profile.LegalName().Equals(name) {
			t.Errorf("expected legal name to remain %v, got %v", name, profile.LegalName())
		}
		if !profile.DateOfBirth().Equals(dob) {
			t.Errorf("expected DOB to remain %v, got %v", dob, profile.DateOfBirth())
		}
		if profile.Version() != 2 {
			t.Errorf("expected version 2, got %d", profile.Version())
		}
		if !profile.UpdatedAt().Equal(t1) {
			t.Errorf("expected UpdatedAt %v, got %v", t1, profile.UpdatedAt())
		}
	})

	t.Run("UpdatePhone updates phone independently", func(t *testing.T) {
		t2 := t1.Add(1 * time.Hour)
		anotherPhone, _ := domain.NewPhone("+2348031234567")

		if err := profile.UpdatePhone(anotherPhone, t2); err != nil {
			t.Fatalf("unexpected error updating phone: %v", err)
		}
		if !profile.Phone().Equals(anotherPhone) {
			t.Errorf("expected phone %v, got %v", anotherPhone, profile.Phone())
		}
		if profile.Version() != 3 {
			t.Errorf("expected version 3, got %d", profile.Version())
		}
	})

	t.Run("UpdateAddress updates address independently", func(t *testing.T) {
		t3 := t1.Add(2 * time.Hour)
		anotherAddr, _ := domain.NewAddress("500 Howard St", "", "San Francisco", "CA", "94105", "US")

		if err := profile.UpdateAddress(anotherAddr, t3); err != nil {
			t.Fatalf("unexpected error updating address: %v", err)
		}
		if !profile.Address().Equals(anotherAddr) {
			t.Errorf("expected address %v, got %v", anotherAddr, profile.Address())
		}
		if profile.Version() != 4 {
			t.Errorf("expected version 4, got %d", profile.Version())
		}
	})
}

