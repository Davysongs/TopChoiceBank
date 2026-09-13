package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type PasswordHashParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultPasswordHashParams = PasswordHashParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

const (
	minSaltLength        = 8
	maxSaltLength        = 64
	minHashLength        = 16
	maxHashLength        = 64
	maxArgon2MemoryKiB   = 1024 * 1024
	maxArgon2Iterations  = 10
	maxArgon2Parallelism = 32
	maxEncodedHashLength = 1024
)

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	salt, err := generateSalt(int(DefaultPasswordHashParams.SaltLength))
	if err != nil {
		return "", err
	}

	return hash(password, DefaultPasswordHashParams, salt), nil
}

func VerifyPassword(password, encodedHash string) bool {
	if password == "" || encodedHash == "" {
		return false
	}

	params, salt, expectedHash, ok := parseEncodedPasswordHash(encodedHash)
	if !ok {
		return false
	}
	if !isSafePasswordHash(params, salt, expectedHash) {
		return false
	}

	actualHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}

func hash(password string, params PasswordHashParams, salt []byte) string {
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d,k=%d$%s$%s",
		params.Memory,
		params.Iterations,
		params.Parallelism,
		params.KeyLength,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func parseEncodedPasswordHash(encoded string) (PasswordHashParams, []byte, []byte, bool) {
	if len(encoded) > maxEncodedHashLength {
		return PasswordHashParams{}, nil, nil, false
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return PasswordHashParams{}, nil, nil, false
	}
	if parts[1] != "argon2id" {
		return PasswordHashParams{}, nil, nil, false
	}
	if parts[2] != "v=19" {
		return PasswordHashParams{}, nil, nil, false
	}

	params, err := parsePasswordHashParams(parts[3])
	if err != nil {
		return PasswordHashParams{}, nil, nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return PasswordHashParams{}, nil, nil, false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return PasswordHashParams{}, nil, nil, false
	}
	return params, salt, expected, true
}

func isSafePasswordHash(params PasswordHashParams, salt, expectedHash []byte) bool {
	if params.Memory == 0 || params.Memory > maxArgon2MemoryKiB {
		return false
	}
	if params.Iterations == 0 || params.Iterations > maxArgon2Iterations {
		return false
	}
	if params.Parallelism == 0 || params.Parallelism > maxArgon2Parallelism {
		return false
	}
	if params.KeyLength == 0 || params.KeyLength > maxHashLength {
		return false
	}
	if uint32(len(expectedHash)) != params.KeyLength || len(expectedHash) < minHashLength {
		return false
	}
	if len(salt) < minSaltLength || len(salt) > maxSaltLength {
		return false
	}
	return true
}

func parsePasswordHashParams(encoded string) (PasswordHashParams, error) {
	parts := strings.Split(encoded, ",")
	if len(parts) != 4 {
		return PasswordHashParams{}, fmt.Errorf("invalid encoded params: %s", encoded)
	}

	memory, err := parseUint32Part(parts[0], "m=")
	if err != nil {
		return PasswordHashParams{}, err
	}
	iterations, err := parseUint32Part(parts[1], "t=")
	if err != nil {
		return PasswordHashParams{}, err
	}
	parallelism, err := parseUint8Part(parts[2], "p=")
	if err != nil {
		return PasswordHashParams{}, err
	}
	keyLength, err := parseUint32Part(parts[3], "k=")
	if err != nil {
		return PasswordHashParams{}, err
	}

	return PasswordHashParams{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		KeyLength:   keyLength,
	}, nil
}

func parseUint32Part(value, prefix string) (uint32, error) {
	raw := strings.TrimPrefix(value, prefix)
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}

func parseUint8Part(value, prefix string) (uint8, error) {
	raw := strings.TrimPrefix(value, prefix)
	parsed, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		return 0, err
	}
	return uint8(parsed), nil
}
