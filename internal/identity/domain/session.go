package domain

import (
	"fmt"
	"time"
)

type Session struct {
	ID                   string
	UserID               string
	DeviceID             *string
	RefreshFamilyID      string
	AccessTokenJTI       string
	RefreshTokenHash     string
	RotatedFromSessionID *string
	IssuedAt             time.Time
	ExpiresAt            time.Time
	LastUsedAt           *time.Time
	RevokedAt            *time.Time
	RevokeReason         *string
	CreatedIP            string
	UserAgent            string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type SessionInput struct {
	ID                   string
	UserID               string
	DeviceID             *string
	RefreshFamilyID      string
	AccessTokenJTI       string
	RefreshTokenHash     string
	RotatedFromSessionID *string
	IssuedAt             time.Time
	ExpiresAt            time.Time
	CreatedIP            string
	UserAgent            string
}

func NewSession(input SessionInput) (*Session, error) {
	if input.ID == "" {
		return nil, ErrMissingSessionID
	}
	if input.UserID == "" {
		return nil, ErrMissingUserID
	}
	if input.RefreshFamilyID == "" {
		return nil, ErrMissingRefreshFamilyID
	}
	if input.AccessTokenJTI == "" {
		return nil, ErrMissingAccessTokenJTI
	}
	if input.RefreshTokenHash == "" {
		return nil, ErrMissingRefreshTokenHash
	}
	if input.UserAgent == "" || len(input.UserAgent) > 512 {
		return nil, fmt.Errorf("invalid user agent")
	}
	if input.CreatedIP == "" {
		return nil, fmt.Errorf("invalid created IP")
	}
	if input.IssuedAt.IsZero() {
		input.IssuedAt = time.Now().UTC()
	}
	if input.ExpiresAt.IsZero() {
		input.ExpiresAt = input.IssuedAt.Add(15 * time.Minute)
	}
	if !input.ExpiresAt.After(input.IssuedAt) {
		return nil, fmt.Errorf("expires_at must be after issued_at")
	}

	return &Session{
		ID:                   input.ID,
		UserID:               input.UserID,
		DeviceID:             input.DeviceID,
		RefreshFamilyID:      input.RefreshFamilyID,
		AccessTokenJTI:       input.AccessTokenJTI,
		RefreshTokenHash:     input.RefreshTokenHash,
		RotatedFromSessionID: input.RotatedFromSessionID,
		IssuedAt:             input.IssuedAt,
		ExpiresAt:            input.ExpiresAt,
		CreatedIP:            input.CreatedIP,
		UserAgent:            input.UserAgent,
		CreatedAt:            input.IssuedAt,
		UpdatedAt:            input.IssuedAt,
	}, nil
}

func (s *Session) IsExpired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}

func (s *Session) IsActive(now time.Time) bool {
	if s == nil {
		return false
	}
	if s.RevokedAt != nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !s.IsExpired(now)
}

func (s *Session) Revoke(reason string, at time.Time) {
	if s == nil || s.RevokedAt != nil {
		return
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	reasonText := reason
	s.RevokedAt = &at
	s.RevokeReason = &reasonText
	s.UpdatedAt = at
}

func (s *Session) Validate(now time.Time) error {
	if s == nil {
		return ErrSessionRevoked
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !s.IsActive(now) {
		if s.RevokedAt != nil {
			return ErrSessionRevoked
		}
		return ErrSessionExpired
	}
	return nil
}
