package domain

import (
	"strings"
	"time"
)

const (
	userPasswordHashAlgorithmArgon2ID = "argon2id"
)

type UserStatus string

const (
	UserStatusPending  UserStatus = "PENDING"
	UserStatusActive   UserStatus = "ACTIVE"
	UserStatusLocked   UserStatus = "LOCKED"
	UserStatusDisabled UserStatus = "DISABLED"
)

type User struct {
	ID                     string
	Email                  string
	PasswordHash           string
	PasswordHashAlgorithm  string
	Status                 UserStatus
	PreLockoutStatus       UserStatus
	EmailVerifiedAt        *time.Time
	FailedLoginCount       int
	FailedLoginWindowStart *time.Time
	LockedUntil            *time.Time
	PasswordChangedAt      time.Time
	Version                int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

func NewUser(id string, email string, passwordHash string, now time.Time) (*User, error) {
	if strings.TrimSpace(id) == "" {
		return nil, ErrInvalidIdentifier
	}
	if strings.TrimSpace(email) == "" {
		return nil, ErrInvalidEmail
	}
	if strings.TrimSpace(passwordHash) == "" {
		return nil, ErrInvalidPasswordHash
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	return &User{
		ID:                    strings.TrimSpace(id),
		Email:                 strings.ToLower(strings.TrimSpace(email)),
		PasswordHash:          passwordHash,
		PasswordHashAlgorithm: userPasswordHashAlgorithmArgon2ID,
		Status:                UserStatusPending,
		PasswordChangedAt:     now,
		Version:               1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}, nil
}

func (u *User) IsLocked(now time.Time) bool {
	if u == nil || u.LockedUntil == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return now.Before(*u.LockedUntil)
}

func (u *User) RecordFailedLogin(now time.Time, lockoutWindow time.Duration, lockoutDuration time.Duration, maxAttempts int) {
	if u == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	u.UpdatedAt = now
	if u.Status == UserStatusLocked {
		if u.LockedUntil == nil || !u.IsLocked(now) {
			if u.PreLockoutStatus != "" {
				u.Status = u.PreLockoutStatus
				u.PreLockoutStatus = ""
			} else {
				u.Status = UserStatusActive
			}
			u.LockedUntil = nil
			u.FailedLoginCount = 0
			u.FailedLoginWindowStart = &now
		}
	}

	if u.FailedLoginWindowStart == nil || now.Sub(*u.FailedLoginWindowStart) > lockoutWindow {
		u.FailedLoginWindowStart = &now
		u.FailedLoginCount = 0
	}

	u.FailedLoginCount++
	if u.FailedLoginCount >= maxAttempts {
		until := now.Add(lockoutDuration)
		u.LockedUntil = &until
		if u.Status != UserStatusLocked {
			u.PreLockoutStatus = u.Status
			u.Status = UserStatusLocked
		}
	}
}

func (u *User) RecordSuccessfulLogin(now time.Time) {
	if u == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	u.UpdatedAt = now
	u.FailedLoginCount = 0
	u.FailedLoginWindowStart = nil
	u.LockedUntil = nil
	if u.Status == UserStatusPending {
		u.Status = UserStatusActive
	}
}
