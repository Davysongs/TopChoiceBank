package domain

import "time"

type RefreshFamily struct {
	ID         string
	UserID     string
	Reason     string
	RevokedAt  *time.Time
	RevokedWhy *string
	LastUsedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func NewRefreshFamily(id string, userID string, createdAt time.Time) (*RefreshFamily, error) {
	if id == "" {
		return nil, ErrInvalidIdentifier
	}
	if userID == "" {
		return nil, ErrMissingUserID
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	return &RefreshFamily{
		ID:        id,
		UserID:    userID,
		Reason:    "created",
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
	}, nil
}

func (f *RefreshFamily) IsRevoked() bool {
	return f != nil && f.RevokedAt != nil
}

func (f *RefreshFamily) Revoke(reason string, now time.Time) {
	if f == nil {
		return
	}
	if f.RevokedAt != nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	reasonText := reason
	f.RevokedAt = &now
	f.RevokedWhy = &reasonText
	f.UpdatedAt = now
}
