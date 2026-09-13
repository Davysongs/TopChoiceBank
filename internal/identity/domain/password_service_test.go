package domain

import "testing"

func TestArgon2idPasswordHasherRoundTrip(t *testing.T) {
	hasher := Argon2idPasswordHasher{}

	hashed, err := hasher.Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasher.Verify("correct-horse-battery-staple", hashed) {
		t.Fatal("expected valid password to verify")
	}
	if hasher.Verify("wrong-password", hashed) {
		t.Fatal("expected invalid password to fail")
	}
}
