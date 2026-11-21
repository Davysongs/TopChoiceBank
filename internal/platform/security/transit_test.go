package security

import (
	"context"
	"testing"
)

// TestAESGCMTransitEncryptor_Roundtrip verifies encryption and decryption roundtrip.
func TestAESGCMTransitEncryptor_Roundtrip(t *testing.T) {
	enc, err := NewAESGCMTransitEncryptor("my-test-transit-secret-key", 1)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	secretPayload := []byte("JBSWY3DPEHPK3PXP") // typical base32 TOTP secret

	ciphertext, keyVersion, err := enc.Encrypt(context.Background(), secretPayload)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	if keyVersion != 1 {
		t.Errorf("expected key version 1, got %d", keyVersion)
	}
	if string(ciphertext) == string(secretPayload) {
		t.Fatal("ciphertext must not match plaintext")
	}

	decrypted, err := enc.Decrypt(context.Background(), ciphertext, keyVersion)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != string(secretPayload) {
		t.Fatalf("expected %q, got %q", string(secretPayload), string(decrypted))
	}

	// Test invalid key version
	_, err = enc.Decrypt(context.Background(), ciphertext, 2)
	if err != ErrInvalidKeyVersion {
		t.Errorf("expected ErrInvalidKeyVersion, got %v", err)
	}

	// Test tampered ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF
	_, err = enc.Decrypt(context.Background(), tampered, keyVersion)
	if err != ErrTransitDecryptionFailed {
		t.Errorf("expected ErrTransitDecryptionFailed, got %v", err)
	}

	// Test identical key re-registration succeeds
	if err := enc.AddKeyVersion(1, "my-test-transit-secret-key"); err != nil {
		t.Errorf("expected identical key registration to succeed, got %v", err)
	}

	// Test conflicting key registration fails
	if err := enc.AddKeyVersion(1, "different-conflicting-secret"); err == nil {
		t.Error("expected conflicting key registration to fail, got nil")
	}
}
