package domain

import "github.com/Davysongs/TopChoiceBank/internal/platform/security"

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password string, encodedHash string) bool
}

type Argon2idPasswordHasher struct{}

func (Argon2idPasswordHasher) Hash(password string) (string, error) {
	return security.HashPassword(password)
}

func (Argon2idPasswordHasher) Verify(password, encodedHash string) bool {
	return security.VerifyPassword(password, encodedHash)
}
