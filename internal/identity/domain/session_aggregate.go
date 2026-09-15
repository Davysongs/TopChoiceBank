package domain

import "time"

type SessionAggregate struct {
	Family  *RefreshFamily
	Session *Session
}

func NewSessionAggregate(family *RefreshFamily, session *Session) (*SessionAggregate, error) {
	if family == nil {
		return nil, ErrFamilyRevoked
	}
	if session == nil {
		return nil, ErrMissingSessionID
	}
	if family.UserID != session.UserID || family.ID != session.RefreshFamilyID {
		return nil, ErrAggregateMismatch
	}

	return &SessionAggregate{
		Family:  family,
		Session: session,
	}, nil
}

func (agg *SessionAggregate) Rotate(now time.Time, replacement SessionInput) (*Session, error) {
	if agg == nil || agg.Session == nil || agg.Family == nil {
		return nil, ErrAggregateMismatch
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if agg.Family.IsRevoked() {
		return nil, ErrFamilyRevoked
	}
	if err := agg.Session.Validate(now); err != nil {
		return nil, err
	}
	if replacement.UserID != agg.Session.UserID {
		return nil, ErrAggregateMismatch
	}
	if replacement.RefreshFamilyID != agg.Family.ID {
		return nil, ErrAggregateMismatch
	}

	replacement.RotatedFromSessionID = &agg.Session.ID
	replacement.IssuedAt = now

	rotated, err := NewSession(replacement)
	if err != nil {
		return nil, err
	}

	agg.Session.Revoke("rotated", now)
	agg.Session = rotated
	agg.Family.LastUsedAt = &now
	agg.Family.UpdatedAt = now

	return rotated, nil
}

func (agg *SessionAggregate) RevokeFamily(reason string, at time.Time) {
	if agg == nil || agg.Family == nil {
		return
	}
	agg.Family.Revoke(reason, at)
	if agg.Session != nil {
		agg.Session.Revoke(reason, at)
	}
}
