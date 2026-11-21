package domain

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TestMFAFactor_Lifecycle verifies pending, activation, and revocation transitions.
func TestMFAFactor_Lifecycle(t *testing.T) {
	now := time.Now().UTC()
	factor, err := NewPendingTOTPFactor("user-123", "Personal Authenticator", []byte("secret"), 1, now)
	if err != nil {
		t.Fatalf("failed to create factor: %v", err)
	}

	if factor.Status() != FactorStatusPending {
		t.Errorf("expected PENDING status, got %s", factor.Status())
	}
	if factor.VerifiedAt() != nil {
		t.Errorf("verifiedAt should be nil for pending factor")
	}

	// Activate factor
	t1 := now.Add(time.Minute)
	if err := factor.Activate(t1); err != nil {
		t.Fatalf("failed to activate factor: %v", err)
	}
	if factor.Status() != FactorStatusActive {
		t.Errorf("expected ACTIVE status, got %s", factor.Status())
	}
	if factor.VerifiedAt() == nil || !factor.VerifiedAt().Equal(t1) {
		t.Errorf("expected verifiedAt %v, got %v", t1, factor.VerifiedAt())
	}

	// Redundant activation should fail
	if err := factor.Activate(t1); err != ErrFactorAlreadyActive {
		t.Errorf("expected ErrFactorAlreadyActive, got %v", err)
	}

	// Revoke factor
	t2 := now.Add(2 * time.Minute)
	if err := factor.Revoke(t2); err != nil {
		t.Fatalf("failed to revoke factor: %v", err)
	}
	if factor.Status() != FactorStatusRevoked {
		t.Errorf("expected REVOKED status, got %s", factor.Status())
	}
	if factor.RevokedAt() == nil || !factor.RevokedAt().Equal(t2) {
		t.Errorf("expected revokedAt %v, got %v", t2, factor.RevokedAt())
	}
}

// TestTOTP_GenerationAndVerification verifies code generation and verification within tolerance.
func TestTOTP_GenerationAndVerification(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}
	if len(secret) < 16 {
		t.Fatalf("generated secret too short: %s", secret)
	}

	now := time.Now().UTC()
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	valid, err := VerifyTOTPCode(secret, code, now)
	if err != nil || !valid {
		t.Fatalf("expected valid code at now, got %v (err: %v)", valid, err)
	}

	// Code should also be valid at skew = +25s (same period or skew)
	validSkew, _ := VerifyTOTPCode(secret, code, now.Add(25*time.Second))
	if !validSkew {
		t.Errorf("expected code to be valid within 25s window")
	}

	// Code should be invalid far outside window (e.g. 5 minutes later)
	invalidFar, _ := VerifyTOTPCode(secret, code, now.Add(5*time.Minute))
	if invalidFar {
		t.Errorf("expected code to be invalid far outside tolerance window")
	}

	// Malformed code should return false without error
	invalidMalformed, _ := VerifyTOTPCode(secret, "123", now)
	if invalidMalformed {
		t.Errorf("expected 3-digit code to be invalid")
	}

	// Deterministic fixture for out-of-window TOTP verification
	deterministicSecret := "JBSWY3DPEHPK3PXP" // standard RFC base32 secret
	fixedTime := time.Unix(1700000000, 0).UTC()
	fixedCode, err := totp.GenerateCodeCustom(deterministicSecret, fixedTime, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("failed to generate fixed code: %v", err)
	}
	validFixed, _ := VerifyTOTPCode(deterministicSecret, fixedCode, fixedTime)
	if !validFixed {
		t.Fatalf("expected deterministic code to be valid at fixture time")
	}
	invalidFixedFar, _ := VerifyTOTPCode(deterministicSecret, fixedCode, fixedTime.Add(10*time.Minute))
	if invalidFixedFar {
		t.Fatalf("expected deterministic code to be invalid far out of window")
	}
}

// TestBackupCodes_GenerationAndHashing verifies backup code formatting and deterministic hashing.
func TestBackupCodes_GenerationAndHashing(t *testing.T) {
	plainCodes, hashes, err := GenerateBackupCodes(10)
	if err != nil {
		t.Fatalf("failed to generate backup codes: %v", err)
	}
	if len(plainCodes) != 10 || len(hashes) != 10 {
		t.Fatalf("expected 10 codes and hashes, got %d and %d", len(plainCodes), len(hashes))
	}

	for i := 0; i < 10; i++ {
		code := plainCodes[i]
		if len(code) != 35 || code[8] != '-' || code[17] != '-' || code[26] != '-' {
			t.Fatalf("unexpected backup code format: %s", code)
		}
		expectedHash := HashBackupCode(code)
		if string(expectedHash) != string(hashes[i]) {
			t.Errorf("hash mismatch for code %s", code)
		}

		// Verify case and hyphen insensitivity
		variedCode := " " + code[:8] + code[9:17] + code[18:26] + code[27:] + " "
		if string(HashBackupCode(variedCode)) != string(hashes[i]) {
			t.Errorf("hash should be hyphen and whitespace insensitive")
		}
	}
}
