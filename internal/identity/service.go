package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Davysongs/TopChoiceBank/internal/identity/domain"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
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
	BackupCode        string `json:"backup_code,omitempty"`
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
	MFAFactorID  string `json:"mfa_factor_id,omitempty"`
}

type RefreshRequest struct {
	RefreshToken      string `json:"refresh_token"`
	DeviceFingerprint string `json:"device_fingerprint"`
	RequestIP         string `json:"-"`
	UserAgent         string `json:"-"`
	RequestID         string `json:"-"`
}

type EnrollTOTPRequest struct {
	UserID    string `json:"-"`
	Password  string `json:"password"`
	Label     string `json:"label"`
	RequestIP string `json:"-"`
	RequestID string `json:"-"`
}

type EnrollTOTPResponse struct {
	FactorID    string    `json:"factor_id"`
	OtpauthURI  string    `json:"otpauth_uri"`
	BackupCodes []string  `json:"backup_codes"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type VerifyTOTPRequest struct {
	UserID    string `json:"-"`
	FactorID  string `json:"factor_id,omitempty"`
	TOTPCode  string `json:"code"`
	RequestIP string `json:"-"`
	RequestID string `json:"-"`
}

type VerifyTOTPResponse struct {
	FactorID   string    `json:"factor_id"`
	Status     string    `json:"status"`
	VerifiedAt time.Time `json:"verified_at"`
}

type ChangePasswordRequest struct {
	UserID          string `json:"-"`
	CurrentPassword string `json:"current_password,omitempty"`
	OldPassword     string `json:"old_password,omitempty"`
	NewPassword     string `json:"new_password"`
	TOTPCode        string `json:"totp_code,omitempty"`
	BackupCode      string `json:"backup_code,omitempty"`
	RecentMFA       bool   `json:"-"`
	RequestIP       string `json:"-"`
	RequestID       string `json:"-"`
}

type ChangePasswordResponse struct {
	ChangedAt       time.Time `json:"changed_at"`
	RevokedSessions int       `json:"revoked_sessions"`
}

type Service struct {
	repo      Repository
	jwtSecret string
	hasher    domain.PasswordHasher
	encryptor security.TransitEncryptor
}

// NewService creates an identity service with the supplied repository and JWT secret.
func NewService(repo Repository, jwtSecret string) *Service {
	enc, _ := security.NewAESGCMTransitEncryptor(jwtSecret, 1)
	return &Service{
		repo:      repo,
		jwtSecret: jwtSecret,
		hasher:    domain.Argon2idPasswordHasher{},
		encryptor: enc,
	}
}

// WithTransitEncryptor overrides the default transit encryptor.
func (s *Service) WithTransitEncryptor(encryptor security.TransitEncryptor) *Service {
	s.encryptor = encryptor
	return s
}

// JWTSecret returns the service JWT signing secret.
func (s *Service) JWTSecret() string {
	return s.jwtSecret
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
	if utf8.RuneCountInString(req.Password) < 8 {
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

	activeFactor, err := s.repo.GetActiveTOTPFactor(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	mfaVerified := false
	var (
		totpFactorID   string
		matchedStep    int64
		backupCodeHash []byte
	)

	if activeFactor != nil {
		if strings.TrimSpace(req.TOTPCode) == "" && strings.TrimSpace(req.BackupCode) == "" {
			return &LoginResponse{
				MFARequired: true,
				MFAFactorID: activeFactor.ID(),
			}, nil
		}
		if strings.TrimSpace(req.TOTPCode) != "" {
			secretBytes, err := s.encryptor.Decrypt(ctx, activeFactor.EncryptedSecret(), activeFactor.KeyVersion())
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt factor secret: %w", err)
			}

			cleanCode := strings.TrimSpace(req.TOTPCode)
			currentStep := now.Unix() / 30
			var validStep int64 = 0
			for step := currentStep - 1; step <= currentStep+1; step++ {
				expectedCode, err := totp.GenerateCodeCustom(string(secretBytes), time.Unix(step*30, 0), totp.ValidateOpts{
					Period:    30,
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				})
				if err == nil && subtle.ConstantTimeCompare([]byte(expectedCode), []byte(cleanCode)) == 1 {
					validStep = step
					break
				}
			}

			if validStep == 0 || (activeFactor.LastTOTPStep() > 0 && validStep <= activeFactor.LastTOTPStep()) {
				user.RecordFailedLogin(now, lockoutWindow, lockoutDuration, maxAttempts)
				_ = s.repo.UpdateUserStatusAndLockout(ctx, user)
				_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.mfa_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "invalid_totp", "failed_count": user.FailedLoginCount})
				if user.Status == domain.UserStatusLocked {
					_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.account_locked.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"locked_until": user.LockedUntil})
					return nil, ErrAccountLocked
				}
				return nil, domain.ErrInvalidTOTPCode
			}

			totpFactorID = activeFactor.ID()
			matchedStep = validStep
			mfaVerified = true
		} else if strings.TrimSpace(req.BackupCode) != "" {
			backupCodeHash = domain.HashBackupCode(req.BackupCode)
			mfaVerified = true
		}
	}

	// Load user roles before creating session to ensure failed role lookup does not consume backup code
	roles, err := s.repo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user roles: %w", err)
	}
	if len(roles) == 0 {
		roles = []string{}
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

	mfaInput := SessionMFAInput{
		ExpectedUserVersion: user.Version,
		TOTPFactorID:        totpFactorID,
		TOTPStep:            matchedStep,
		BackupCodeHash:      backupCodeHash,
	}

	if err := s.repo.CreateSessionAndFamilyWithMFA(ctx, family, session, mfaInput); err != nil {
		if errors.Is(err, domain.ErrInvalidBackupCode) {
			user.RecordFailedLogin(now, lockoutWindow, lockoutDuration, maxAttempts)
			_ = s.repo.UpdateUserStatusAndLockout(ctx, user)
			_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.mfa_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "invalid_backup_code", "failed_count": user.FailedLoginCount})
			if user.Status == domain.UserStatusLocked {
				_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.account_locked.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"locked_until": user.LockedUntil})
				return nil, ErrAccountLocked
			}
			return nil, domain.ErrInvalidBackupCode
		}
		if errors.Is(err, domain.ErrInvalidTOTPCode) {
			user.RecordFailedLogin(now, lockoutWindow, lockoutDuration, maxAttempts)
			_ = s.repo.UpdateUserStatusAndLockout(ctx, user)
			_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.mfa_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "totp_replayed", "failed_count": user.FailedLoginCount})
			if user.Status == domain.UserStatusLocked {
				_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.account_locked.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"locked_until": user.LockedUntil})
				return nil, ErrAccountLocked
			}
			return nil, domain.ErrInvalidTOTPCode
		}
		return nil, err
	}

	// Reset failed login count and record successful login upon complete authentication
	user.RecordSuccessfulLogin(now)
	_ = s.repo.UpdateUserStatusAndLockout(ctx, user)

	scopes := domain.DefaultScopesForRoles(roles)

	amr := []string{"pwd"}
	if mfaVerified {
		amr = append(amr, "mfa")
	}

	claims := security.JWTClaims{
		Subject:   user.ID,
		JTI:       jti,
		Issuer:    "topchoicebank",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(jwtDuration).Unix(),
		Roles:     roles,
		Scopes:    scopes,
		AMR:       amr,
		AuthTime:  now.Unix(),
	}

	accessToken, err := security.GenerateAccessTokenWithClaims(s.jwtSecret, claims)
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
		_ = s.repo.RevokeRefreshFamily(ctx, agg.Family.ID, "reuse_detected")
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
		if strings.TrimSpace(req.DeviceFingerprint) == "" {
			return nil, ErrInvalidCredentials
		}
		fpHash := security.HashToken(req.DeviceFingerprint)
		devID, err := s.repo.GetOrCreateDevice(ctx, user.ID, fpHash, req.UserAgent, formatIP(req.RequestIP))
		if err != nil {
			return nil, err
		}
		if devID != *agg.Session.DeviceID {
			return nil, ErrInvalidCredentials
		}
		deviceIDPtr = agg.Session.DeviceID
	}
	if strings.TrimSpace(req.DeviceFingerprint) != "" {
	} else if strings.TrimSpace(req.DeviceFingerprint) != "" {
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

	// Load roles before rotating session so failure leaves refresh token unrotated and usable for retry
	roles, err := s.repo.GetUserRoles(ctx, agg.Session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user roles: %w", err)
	}
	if len(roles) == 0 {
		roles = []string{}
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

	claims := security.JWTClaims{
		Subject:   agg.Session.UserID,
		JTI:       nextJTI,
		Issuer:    "topchoicebank",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(jwtDuration).Unix(),
		Roles:     roles,
		Scopes:    domain.DefaultScopesForRoles(roles),
		AMR:       []string{"refresh"},
		AuthTime:  now.Unix(),
	}

	accessToken, err := security.GenerateAccessTokenWithClaims(s.jwtSecret, claims)
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

// EnrollTOTP validates current password, creates a Vault-encrypted TOTP factor and hashed backup codes.
func (s *Service) EnrollTOTP(ctx context.Context, req EnrollTOTPRequest) (*EnrollTOTPResponse, error) {
	if strings.TrimSpace(req.UserID) == "" {
		return nil, domain.ErrMissingUserID
	}

	user, err := s.repo.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	if !s.hasher.Verify(req.Password, user.PasswordHash) {
		_ = s.repo.RecordSecurityEvent(ctx, req.UserID, "identity.mfa_enrol_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "invalid_password"})
		return nil, ErrInvalidCredentials
	}

	activeFactor, err := s.repo.GetActiveTOTPFactor(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if activeFactor != nil {
		return nil, domain.ErrFactorAlreadyActive
	}

	secret, err := domain.GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}

	encryptedSecret, keyVersion, err := s.encryptor.Encrypt(ctx, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt totp secret: %w", err)
	}

	plainCodes, hashes, err := domain.GenerateBackupCodes(10)
	if err != nil {
		return nil, err
	}

	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "Personal Authenticator"
	}

	now := time.Now().UTC()
	factor, err := domain.NewPendingTOTPFactor(user.ID, label, encryptedSecret, keyVersion, now)
	if err != nil {
		return nil, err
	}

	if err := s.repo.CreatePendingTOTPFactor(ctx, factor, hashes); err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", "TopChoiceBank")
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")

	labelSegment := url.PathEscape("TopChoiceBank:" + user.Email)
	otpauthURI := fmt.Sprintf("otpauth://totp/%s?%s", labelSegment, q.Encode())

	return &EnrollTOTPResponse{
		FactorID:    factor.ID(),
		OtpauthURI:  otpauthURI,
		BackupCodes: plainCodes,
		ExpiresAt:   now.Add(15 * time.Minute),
	}, nil
}

// VerifyTOTP verifies the supplied 6-digit TOTP code, transitions factor to ACTIVE, and emits identity.mfa_enrolled.v1.
func (s *Service) VerifyTOTP(ctx context.Context, req VerifyTOTPRequest) (*VerifyTOTPResponse, error) {
	if strings.TrimSpace(req.UserID) == "" {
		return nil, domain.ErrMissingUserID
	}

	factor, err := s.repo.GetPendingTOTPFactor(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if factor == nil {
		return nil, errors.New("no pending mfa factor found for verification")
	}

	if strings.TrimSpace(req.FactorID) != "" && req.FactorID != factor.ID() {
		return nil, errors.New("factor ID does not match pending factor")
	}

	now := time.Now().UTC()
	if now.After(factor.CreatedAt().Add(15 * time.Minute)) {
		return nil, domain.ErrMFAEnrollmentExpired
	}

	secretBytes, err := s.encryptor.Decrypt(ctx, factor.EncryptedSecret(), factor.KeyVersion())
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt factor secret: %w", err)
	}

	valid, err := domain.VerifyTOTPCode(string(secretBytes), req.TOTPCode, now)
	if err != nil || !valid {
		_ = s.repo.RecordSecurityEvent(ctx, req.UserID, "identity.mfa_verify_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "invalid_code"})
		return nil, domain.ErrInvalidTOTPCode
	}

	outboxEvent := platformdb.OutboxEventInput{
		AggregateType:    "identity.mfa_factors",
		AggregateID:      factor.ID(),
		AggregateVersion: 1,
		EventType:        "identity.mfa_enrolled.v1",
		SchemaVersion:    1,
		Payload: map[string]any{
			"user_id":     factor.UserID(),
			"factor_id":   factor.ID(),
			"factor_type": factor.FactorType(),
		},
		OccurredAt: now,
	}

	if err := s.repo.ActivateMFAFactorWithOutbox(ctx, factor.ID(), now, outboxEvent); err != nil {
		return nil, err
	}

	_ = s.repo.RecordSecurityEvent(ctx, req.UserID, "identity.mfa_enrolled.v1", "SUCCESS", req.RequestID, req.RequestIP, map[string]any{"factor_id": factor.ID()})

	return &VerifyTOTPResponse{
		FactorID:   factor.ID(),
		Status:     "ACTIVE",
		VerifiedAt: now,
	}, nil
}

// ConsumeBackupCode consumes a single-use backup code.
func (s *Service) ConsumeBackupCode(ctx context.Context, userID, code string) error {
	if strings.TrimSpace(userID) == "" {
		return domain.ErrMissingUserID
	}
	hash := domain.HashBackupCode(code)
	return s.repo.ConsumeBackupCode(ctx, userID, hash)
}

// ChangePassword changes the user password, requiring recent MFA or TOTP/backup code confirmation.
func (s *Service) ChangePassword(ctx context.Context, req ChangePasswordRequest) (*ChangePasswordResponse, error) {
	if strings.TrimSpace(req.UserID) == "" {
		return nil, domain.ErrMissingUserID
	}

	now := time.Now().UTC()
	user, err := s.repo.GetUserByID(ctx, req.UserID)
	if err != nil {
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
		_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.password_change_failed.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"reason": "disabled"})
		return nil, ErrAccountDisabled
	}

	if user.IsLocked(now) {
		_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.password_change_failed.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"reason": "locked"})
		return nil, ErrAccountLocked
	}

	oldPwd := req.CurrentPassword
	if oldPwd == "" {
		oldPwd = req.OldPassword
	}

	if !s.hasher.Verify(oldPwd, user.PasswordHash) {
		user.RecordFailedLogin(now, lockoutWindow, lockoutDuration, maxAttempts)
		_ = s.repo.UpdateUserStatusAndLockout(ctx, user)
		_ = s.repo.RecordSecurityEvent(ctx, req.UserID, "identity.password_change_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "invalid_old_password", "failed_count": user.FailedLoginCount})
		if user.Status == domain.UserStatusLocked {
			_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.account_locked.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"locked_until": user.LockedUntil})
			return nil, ErrAccountLocked
		}
		return nil, ErrInvalidCredentials
	}

	activeFactor, err := s.repo.GetActiveTOTPFactor(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	var backupHash []byte
	if activeFactor != nil {
		if req.RecentMFA {
			// recent MFA verification claim satisfied
		} else if strings.TrimSpace(req.TOTPCode) != "" {
			secretBytes, err := s.encryptor.Decrypt(ctx, activeFactor.EncryptedSecret(), activeFactor.KeyVersion())
			if err != nil {
				return nil, err
			}

			valid, err := domain.VerifyTOTPCode(string(secretBytes), req.TOTPCode, now)
			if err != nil || !valid {
				user.RecordFailedLogin(now, lockoutWindow, lockoutDuration, maxAttempts)
				_ = s.repo.UpdateUserStatusAndLockout(ctx, user)
				_ = s.repo.RecordSecurityEvent(ctx, req.UserID, "identity.password_change_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "invalid_totp", "failed_count": user.FailedLoginCount})
				if user.Status == domain.UserStatusLocked {
					_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.account_locked.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"locked_until": user.LockedUntil})
					return nil, ErrAccountLocked
				}
				return nil, domain.ErrInvalidTOTPCode
			}
		} else if strings.TrimSpace(req.BackupCode) != "" {
			backupHash = domain.HashBackupCode(req.BackupCode)
		} else {
			return nil, errors.New("recent mfa verification or totp code required")
		}
	}

	if utf8.RuneCountInString(req.NewPassword) < 8 {
		return nil, ErrWeakPassword
	}
	if req.NewPassword == oldPwd {
		return nil, errors.New("new password must be different from current password")
	}

	newHash, err := s.hasher.Hash(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash new password: %w", err)
	}

	outboxEvent := platformdb.OutboxEventInput{
		AggregateType: "identity.users",
		AggregateID:   user.ID,
		EventType:     "identity.password_changed.v1",
		SchemaVersion: 1,
		Payload: map[string]any{
			"user_id": user.ID,
		},
		OccurredAt: now,
	}

	revokedCount, err := s.repo.RotatePasswordTx(ctx, user.ID, user.Version, newHash, backupHash, outboxEvent)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidBackupCode) {
			user.RecordFailedLogin(now, lockoutWindow, lockoutDuration, maxAttempts)
			_ = s.repo.UpdateUserStatusAndLockout(ctx, user)
			_ = s.repo.RecordSecurityEvent(ctx, req.UserID, "identity.password_change_failed.v1", "FAILURE", req.RequestID, req.RequestIP, map[string]any{"reason": "invalid_backup_code", "failed_count": user.FailedLoginCount})
			if user.Status == domain.UserStatusLocked {
				_ = s.repo.RecordSecurityEvent(ctx, user.ID, "identity.account_locked.v1", "BLOCKED", req.RequestID, req.RequestIP, map[string]any{"locked_until": user.LockedUntil})
				return nil, ErrAccountLocked
			}
			return nil, domain.ErrInvalidBackupCode
		}
		return nil, err
	}

	user.RecordSuccessfulLogin(now)
	_ = s.repo.UpdateUserStatusAndLockout(ctx, user)

	_ = s.repo.RecordSecurityEvent(ctx, req.UserID, "identity.password_changed.v1", "SUCCESS", req.RequestID, req.RequestIP, nil)

	return &ChangePasswordResponse{
		ChangedAt:       now,
		RevokedSessions: revokedCount,
	}, nil
}
