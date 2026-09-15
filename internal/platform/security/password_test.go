package security

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hashed, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if !VerifyPassword("correct-horse-battery-staple", hashed) {
		t.Fatal("VerifyPassword() expected valid password to verify")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	hashed, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if VerifyPassword("wrong-password", hashed) {
		t.Fatal("VerifyPassword() expected wrong password to fail")
	}
}

func TestHashPasswordRejectsEmptyPassword(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("HashPassword() expected error for empty password")
	}
}

func TestVerifyPasswordRejectsUnsafeEncodedParams(t *testing.T) {
	tests := []string{
		"$argon2id$v=19$m=65536,t=3,p=0,k=32$c29tZXNhbHQ$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY",
		"$argon2id$v=19$m=2000000,t=3,p=2,k=32$c29tZXNhbHQ$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY",
		"$argon2id$v=19$m=65536,t=3,p=2,k=128$c29tZXNhbHQ$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY",
	}

	for _, encoded := range tests {
		if VerifyPassword("correct-horse-battery-staple", encoded) {
			t.Fatalf("VerifyPassword() expected %q to be rejected", encoded)
		}
	}
}

func TestParseEncodedPasswordHashRejectsOversizedInput(t *testing.T) {
	longEncoded := "$argon2id$v=19$m=65536,t=3,p=2,k=32$" + strings.Repeat("A", 2000)
	if _, _, _, ok := parseEncodedPasswordHash(longEncoded); ok {
		t.Fatal("parseEncodedPasswordHash() expected oversized encoded hash to be rejected")
	}
}
