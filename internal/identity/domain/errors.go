package domain

import "errors"

var (
	ErrInvalidIdentifier       = errors.New("identifier is required")
	ErrInvalidEmail            = errors.New("email is required")
	ErrInvalidPasswordHash     = errors.New("password hash is required")
	ErrMissingUserID           = errors.New("user id is required")
	ErrMissingRefreshFamilyID  = errors.New("refresh family id is required")
	ErrMissingSessionID        = errors.New("session id is required")
	ErrMissingAccessTokenJTI   = errors.New("access token jti is required")
	ErrMissingRefreshTokenHash = errors.New("refresh token hash is required")
	ErrSessionExpired          = errors.New("session has expired")
	ErrSessionRevoked          = errors.New("session is revoked")
	ErrFamilyRevoked           = errors.New("refresh family is revoked")
	ErrAggregateMismatch       = errors.New("session and family do not belong to the same user")
)
