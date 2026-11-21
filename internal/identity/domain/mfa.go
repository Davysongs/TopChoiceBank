package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	ErrInvalidFactorType    = errors.New("invalid mfa factor type")
	ErrInvalidFactorStatus  = errors.New("invalid mfa factor status")
	ErrInvalidFactorLabel   = errors.New("invalid mfa factor label")
	ErrFactorAlreadyActive  = errors.New("mfa factor is already active")
	ErrFactorNotPending     = errors.New("mfa factor is not in pending status")
	ErrFactorRevoked        = errors.New("mfa factor is revoked")
	ErrInvalidTOTPCode      = errors.New("invalid or expired totp code")
	ErrInvalidBackupCode    = errors.New("invalid or already consumed backup code")
	ErrMFAEnrollmentExpired = errors.New("mfa enrollment has expired; please enroll again")
)

type FactorStatus string

const (
	FactorStatusPending FactorStatus = "PENDING"
	FactorStatusActive  FactorStatus = "ACTIVE"
	FactorStatusRevoked FactorStatus = "REVOKED"
)

// MFAFactor represents an enrolled multi-factor authentication mechanism for a user.
type MFAFactor struct {
	id              string
	userID          string
	factorType      string
	label           string
	encryptedSecret []byte
	keyVersion      int
	status          FactorStatus
	verifiedAt      *time.Time
	revokedAt       *time.Time
	lastTOTPStep    int64
	createdAt       time.Time
}

// NewPendingTOTPFactor creates a new unverified TOTP factor in PENDING state.
func NewPendingTOTPFactor(
	userID string,
	label string,
	encryptedSecret []byte,
	keyVersion int,
	now time.Time,
) (*MFAFactor, error) {
	trimmedUserID := strings.TrimSpace(userID)
	if trimmedUserID == "" {
		return nil, ErrMissingUserID
	}

	trimmedLabel := strings.TrimSpace(label)
	if len(trimmedLabel) < 1 || len(trimmedLabel) > 80 {
		return nil, ErrInvalidFactorLabel
	}

	if len(encryptedSecret) == 0 {
		return nil, errors.New("encrypted secret is required")
	}

	if keyVersion < 1 {
		return nil, errors.New("key version must be positive")
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	return &MFAFactor{
		id:              uuid.New().String(),
		userID:          trimmedUserID,
		factorType:      "TOTP",
		label:           trimmedLabel,
		encryptedSecret: encryptedSecret,
		keyVersion:      keyVersion,
		status:          FactorStatusPending,
		createdAt:       now,
	}, nil
}

// ReconstituteMFAFactor reconstitutes an existing factor from persistence.
func ReconstituteMFAFactor(
	id string,
	userID string,
	factorType string,
	label string,
	encryptedSecret []byte,
	keyVersion int,
	status FactorStatus,
	verifiedAt *time.Time,
	revokedAt *time.Time,
	lastTOTPStep int64,
	createdAt time.Time,
) (*MFAFactor, error) {
	if factorType != "TOTP" {
		return nil, ErrInvalidFactorType
	}
	switch status {
	case FactorStatusPending:
		if verifiedAt != nil {
			return nil, ErrInvalidFactorStatus
		}
	case FactorStatusActive:
		if verifiedAt == nil {
			return nil, ErrInvalidFactorStatus
		}
	case FactorStatusRevoked:
		if revokedAt == nil {
			return nil, ErrInvalidFactorStatus
		}
	default:
		return nil, ErrInvalidFactorStatus
	}

	return &MFAFactor{
		id:              id,
		userID:          userID,
		factorType:      factorType,
		label:           label,
		encryptedSecret: encryptedSecret,
		keyVersion:      keyVersion,
		status:          status,
		verifiedAt:      verifiedAt,
		revokedAt:       revokedAt,
		lastTOTPStep:    lastTOTPStep,
		createdAt:       createdAt,
	}, nil
}

// ID returns the factor identifier.
func (f *MFAFactor) ID() string { return f.id }

// UserID returns the associated user identifier.
func (f *MFAFactor) UserID() string { return f.userID }

// FactorType returns the factor type (TOTP).
func (f *MFAFactor) FactorType() string { return f.factorType }

// Label returns the factor label.
func (f *MFAFactor) Label() string { return f.label }

// EncryptedSecret returns the Vault-encrypted secret bytes.
func (f *MFAFactor) EncryptedSecret() []byte { return f.encryptedSecret }

// KeyVersion returns the encryption key version.
func (f *MFAFactor) KeyVersion() int { return f.keyVersion }

// Status returns the current factor status.
func (f *MFAFactor) Status() FactorStatus { return f.status }

// VerifiedAt returns the timestamp when the factor was activated.
func (f *MFAFactor) VerifiedAt() *time.Time { return f.verifiedAt }

// RevokedAt returns the timestamp when the factor was revoked.
func (f *MFAFactor) RevokedAt() *time.Time { return f.revokedAt }

// LastTOTPStep returns the last consumed TOTP time step to prevent replay.
func (f *MFAFactor) LastTOTPStep() int64 { return f.lastTOTPStep }

// CreatedAt returns the factor creation timestamp.
func (f *MFAFactor) CreatedAt() time.Time { return f.createdAt }

// Activate transitions a PENDING factor to ACTIVE upon successful verification.
func (f *MFAFactor) Activate(now time.Time) error {
	if f.status == FactorStatusActive {
		return ErrFactorAlreadyActive
	}
	if f.status != FactorStatusPending {
		return ErrFactorNotPending
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	f.status = FactorStatusActive
	f.verifiedAt = &now
	return nil
}

// Revoke transitions an ACTIVE factor to REVOKED.
func (f *MFAFactor) Revoke(now time.Time) error {
	if f.status == FactorStatusRevoked {
		return ErrFactorRevoked
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	f.status = FactorStatusRevoked
	f.revokedAt = &now
	return nil
}

// GenerateTOTPSecret creates a random 20-byte base32 TOTP secret string.
func GenerateTOTPSecret() (string, error) {
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes), nil
}

// GenerateBackupCodes generates count formatted single-use backup codes with at least 128 bits of entropy and their SHA-256 hashes.
func GenerateBackupCodes(count int) ([]string, [][]byte, error) {
	if count <= 0 {
		count = 10
	}

	plainCodes := make([]string, count)
	hashes := make([][]byte, count)

	for i := 0; i < count; i++ {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random backup code: %w", err)
		}
		code := fmt.Sprintf("%08x-%08x-%08x-%08x",
			uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]),
			uint32(b[4])<<24|uint32(b[5])<<16|uint32(b[6])<<8|uint32(b[7]),
			uint32(b[8])<<24|uint32(b[9])<<16|uint32(b[10])<<8|uint32(b[11]),
			uint32(b[12])<<24|uint32(b[13])<<16|uint32(b[14])<<8|uint32(b[15]),
		)
		plainCodes[i] = code
		hashes[i] = HashBackupCode(code)
	}

	return plainCodes, hashes, nil
}

// HashBackupCode normalizes a backup code by trimming leading and trailing whitespace and returns its SHA-256 digest.
func HashBackupCode(code string) []byte {
	clean := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	h := sha256.Sum256([]byte(clean))
	res := make([]byte, len(h))
	copy(res, h[:])
	return res
}

// VerifyTOTPCode verifies a 6-digit TOTP code against a decrypted base32 secret with standard clock drift tolerance using constant-time comparison.
func VerifyTOTPCode(secret string, code string, now time.Time) (bool, error) {
	cleanCode := strings.TrimSpace(code)
	if len(cleanCode) != 6 {
		return false, nil
	}

	currentStep := now.Unix() / 30
	var matched bool
	for step := currentStep - 1; step <= currentStep+1; step++ {
		expectedCode, err := totp.GenerateCodeCustom(secret, time.Unix(step*30, 0), totp.ValidateOpts{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && subtle.ConstantTimeCompare([]byte(expectedCode), []byte(cleanCode)) == 1 {
			matched = true
		}
	}
	return matched, nil
}
