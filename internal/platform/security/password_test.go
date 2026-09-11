package security

import "testing"

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
