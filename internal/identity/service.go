package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/identity/domain"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
	"github.com/google/uuid"
)

var (
	ErrInvalidEmail       = errors.New("invalid email address")
	ErrWeakPassword       = errors.New("password must be at least 8 characters long")
	ErrMissingTerms       = errors.New("accepted terms version is required")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrAccountLocked      = errors.New("account is locked due to too many failed attempts")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrTokenRevoked       = errors.New("refresh token has been revoked")
	ErrTokenExpired       = errors.New("refresh token has expired")
)

const (
	lockoutWindow          = 15 * time.Minute
	lockoutDuration        = 30 * time.Minute
	maxAttempts             = 5
	jwtDuration            = 15 * time.Minute
	refreshSessionDuration = 7 * 24 * time.Hour
)

type RegisterRequest struct {
	Email                string `json:"email"`
	Password             string `json:"password"`
	AcceptedTermsVersion string `json:"accepted_terms_version"`
}

type RegisterResponse struct {
	UserID                   string `json:"user_id"`
	Status                   string `json:"status"`
	EmailVerificationRequired bool   `json:"email_verification_required"`
}

type LoginRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	DeviceFingerprint string `json:"device_fingerprint"`
	TOTPCode          string `json:"totp_code,omitempty"`
	RequestIP         string `json:"-"`
	UserAgent         string `json:"-"`
	RequestID         string `json:"-"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
	MFARequired  bool   `json:"mfa_required"`
}

type RefreshRequest struct {
	RefreshToken      string `json:"refresh_token"`
	DeviceFingerprint string `json:"device_fingerprint"`
	RequestIP         string `json:"-"`
	UserAgent         string `json:"-"`
	RequestID         string `json:"-"`
}

type Service struct {
	repo      Repository
	jwtSecret string
	hasher    domain.PasswordHasher
}

// NewService creates an identity service with the supplied repository and JWT secret.
func NewService(repo Repository, jwtSecret string) *Service {
	return &Service{
		repo:      repo,
		jwtSecret: jwtSecret,
		hasher:    domain.Argon2idPasswordHasher{},
	}
}

// Register validates a registration request and creates a pending customer account.
func (s *Service) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, ErrInvalidEmail
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, ErrInvalidEmail
	}
	if len(req.Password) < 8 {
		return nil, ErrWeakPassword
	}
	if strings.TrimSpace(req.AcceptedTermsVersion) == "" {
		return nil, ErrMissingTerms
	}

	passwordHash, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now().UTC()
	userID := uuid.New().String()

	user, err := domain.NewUser(userID, email, passwordHash, now)
	if err != nil {
		return nil, err
	}

	outboxEvent := platformdb.OutboxEventInput{
		AggregateType:    "identity.users",
		AggregateID:      user.ID,
		AggregateVersion: 1,
		EventType:        "identity.user_registered.v1",
		SchemaVersion:    1,
		Payload: map[string]any{
			"user_id":                user.ID,
			"email":                  user.Email,
			"status":                 string(user.Status),
			"accepted_terms_version": req.AcceptedTermsVersion,
			"accepted_terms_at":      now.Format(time.RFC3339),
		},
		OccurredAt: now,
	}

	if err := s.repo.CreateUserWithOutbox(ctx, user, outboxEvent); err != nil {
		return nil, err
	}

	return &RegisterResponse{
		UserID:                   user.ID,
		Status:                   string(user.Status),
		EmailVerificationRequired: true,
	}, nil
}

// Login authenticates a user and starts a refresh-token session.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		return nil, ErrInvalidCredentials
	}

	now := time.Now().UTC()
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			_ = s.repo.RecordSecurityEvent(ctx, "", "identity.login_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "user_not_found"})
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.Status == domain.UserStatusLocked && !user.IsLocked(now) {
		if user.PreLockoutStatus != "" {
			user.Status = user.PreLockoutStatus
		} else {
			user.Status = domain.UserStatusActive
		}
		user.PreLockoutStatus = ""
		user.LockedUntil = nil
	}

	if user.Status == domain.UserStatusDisabled {
		_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.login_failed.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"reason": "disabled"})
		return nil, ErrAccountDisabled
	}

	if user.IsLocked(now) {
		_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.login_failed.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"reason": "locked"})
		return nil, ErrAccountLocked
	}

	valid := s.hasher.Verify(req.Password, user.PasswordHash)
	if !valid {
		user.RecordFailedLogin(now, lockoutWindow, lockoutDuration, maxAttempts)
		if err := s.repo.UpdateUserStatusAndLockout(ctx, user); err != nil {
			return nil, err
		}
		_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.login_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"failed_count": user.FailedLoginCount})

		if user.Status == domain.UserStatusLocked {
			_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.account_locked.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"locked_until": user.LockedUntil})
			return nil, ErrAccountLocked
		}
		return nil, ErrInvalidCredentials
	}

	user.RecordSuccessfulLogin(now)
	if err := s.repo.UpdateUserStatusAndLockout(ctx, user); err != nil {
		return nil, err
	}

	var deviceIDPtr *string
	if strings.TrimSpace(req.DeviceFingerprint) != "" {
		fpHash := security.HashToken(req.DeviceFingerprint)
		devID, err := s.repo.GetOrCreateDevice(ctx, user.ID, fpHash, req.UserAgent, formatIP(req.RequestIP))
		if err != nil {
			return nil, err
		}
		deviceIDPtr = &devID
	}

	familyID := uuid.New().String()
	family, err := domain.NewRefreshFamily(familyID, user.ID, now)
	if err != nil {
		return nil, err
	}

	refreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshTokenStr := hex.EncodeToString(refreshTokenBytes)
	refreshTokenHash := security.HashToken(refreshTokenStr)

	jti := uuid.New().String()
	sessionID := uuid.New().String()
	sessionInput := domain.SessionInput{
		ID:               sessionID,
		UserID:           user.ID,
		DeviceID:         deviceIDPtr,
		RefreshFamilyID:  familyID,
		AccessTokenJTI:   jti,
		RefreshTokenHash: hex.EncodeToString(refreshTokenHash),
		IssuedAt:         now,
		ExpiresAt:        now.Add(refreshSessionDuration),
		CreatedIP:        formatIP(req.RequestIP),
		UserAgent:        formatUserAgent(req.UserAgent),
	}

	session, err := domain.NewSession(sessionInput)
	if err != nil {
		return nil, err
	}

	if err := s.repo.CreateSessionAndFamily(ctx, family, session); err != nil {
		return nil, err
	}

	accessToken, err := security.GenerateAccessToken(s.jwtSecret, user.ID, jti, now, jwtDuration)
	if err != nil {
		return nil, err
	}

	_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.login_succeeded.v1", "SUCCESS", req.RequestID, req.RequestIP, map[string]any{"session_id": sessionID})

	return &LoginResponse{
		AccessToken:  accessToken,
		ExpiresIn:    int(jwtDuration.Seconds()),
		RefreshToken: refreshTokenStr,
		SessionID:    sessionID,
		MFARequired:  false,
	}, nil
}

// RefreshSession rotates a valid refresh token and issues a new token pair.
func (s *Service) RefreshSession(ctx context.Context, req RefreshRequest) (*LoginResponse, error) {
	if strings.TrimSpace(req.RefreshToken) == "" {
		return nil, ErrInvalidCredentials
	}

	now := time.Now().UTC()
	refreshTokenHash := security.HashToken(req.RefreshToken)
	hashHex := hex.EncodeToString(refreshTokenHash)

	agg, err := s.repo.GetSessionAndFamilyByRefreshTokenHash(ctx, []byte(hashHex))
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Token reuse detection
	if agg.Family.IsRevoked() || agg.Session.RevokedAt != nil {
		if revokeErr := s.repo.RevokeRefreshFamily(ctx, agg.Family.ID, "reuse_detected"); revokeErr != nil {
			return nil, revokeErr
		}
		_ = s.repo.RecordSecurityEvent(ctx, agg.Session.UserID, "identity.refresh_reuse_detected.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"family_id": agg.Family.ID})
		return nil, ErrTokenRevoked
	}

	user, err := s.repo.GetUserByID(ctx, agg.Session.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.Status == domain.UserStatusDisabled {
		return nil, ErrAccountDisabled
	}
	if user.IsLocked(now) {
		return nil, ErrAccountLocked
	}

	if agg.Session.IsExpired(now) {
		return nil, ErrTokenExpired
	}

	var deviceIDPtr *string
	if agg.Session.DeviceID != nil {
		deviceIDPtr = agg.Session.DeviceID
	}
	if strings.TrimSpace(req.DeviceFingerprint) != "" {
		fpHash := security.HashToken(req.DeviceFingerprint)
		devID, err := s.repo.GetOrCreateDevice(ctx, user.ID, fpHash, req.UserAgent, formatIP(req.RequestIP))
		if err != nil {
			return nil, err
		}
		deviceIDPtr = &devID
	}

	nextRefreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(nextRefreshTokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	nextRefreshTokenStr := hex.EncodeToString(nextRefreshTokenBytes)
	nextRefreshTokenHash := security.HashToken(nextRefreshTokenStr)

	nextJTI := uuid.New().String()
	nextSessionID := uuid.New().String()

	replacement := domain.SessionInput{
		ID:               nextSessionID,
		UserID:           agg.Session.UserID,
		DeviceID:         deviceIDPtr,
		RefreshFamilyID:  agg.Family.ID,
		AccessTokenJTI:   nextJTI,
		RefreshTokenHash: hex.EncodeToString(nextRefreshTokenHash),
		ExpiresAt:        now.Add(refreshSessionDuration),
		CreatedIP:        formatIP(req.RequestIP),
		UserAgent:        formatUserAgent(req.UserAgent),
	}

	oldSessionID := agg.Session.ID
	rotatedSession, err := agg.Rotate(now, replacement)
	if err != nil {
		return nil, err
	}

	if err := s.repo.RotateSession(ctx, oldSessionID, agg, rotatedSession); err != nil {
		if errors.Is(err, ErrSessionAlreadyRevoked) {
			if revokeErr := s.repo.RevokeRefreshFamily(ctx, agg.Family.ID, "reuse_detected"); revokeErr != nil {
				return nil, revokeErr
			}
			_ = s.repo.RecordSecurityEvent(ctx, agg.Session.UserID, "identity.refresh_reuse_detected.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"family_id": agg.Family.ID})
			return nil, ErrTokenRevoked
		}
		return nil, err
	}

	accessToken, err := security.GenerateAccessToken(s.jwtSecret, agg.Session.UserID, nextJTI, now, jwtDuration)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		ExpiresIn:    int(jwtDuration.Seconds()),
		RefreshToken: nextRefreshTokenStr,
		SessionID:    nextSessionID,
		MFARequired:  false,
	}, nil
}

// formatIP normalizes a request address for storage as an IP value.
func formatIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "127.0.0.1"
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}

// formatUserAgent normalizes and bounds a user-agent value for storage.
func formatUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "unknown"
	}
	if len(ua) > 512 {
		return ua[:512]
	}
	return ua
}
