package security

import (
	"testing"
	"time"
)

func TestGenerateAndVerifyAccessToken(t *testing.T) {
	secret := "test-secret-key-32-bytes-long!!"
	userID := "user-123"
	jti := "jti-456"
	now := time.Now().UTC()

	token, err := GenerateAccessToken(secret, userID, jti, now, 15*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	claims, err := VerifyAccessToken(secret, token, now)
	if err != nil {
		t.Fatalf("unexpected error verifying token: %v", err)
	}

	if claims.Subject != userID {
		t.Errorf("expected subject %s, got %s", userID, claims.Subject)
	}
	if claims.JTI != jti {
		t.Errorf("expected JTI %s, got %s", jti, claims.JTI)
	}
}

func TestVerifyAccessTokenExpired(t *testing.T) {
	secret := "test-secret-key-32-bytes-long!!"
	now := time.Now().UTC()
	past := now.Add(-20 * time.Minute)

	token, err := GenerateAccessToken(secret, "user-123", "jti-789", past, 15*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	_, err = VerifyAccessToken(secret, token, now)
	if err != ErrExpiredToken {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

