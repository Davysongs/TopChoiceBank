package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

type JWTClaims struct {
	Subject   string `json:"sub"`
	JTI       string `json:"jti"`
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type TokenPair struct {
	AccessToken  string
	ExpiresIn    int
	RefreshToken string
	SessionID    string
}

func GenerateAccessToken(secret string, userID string, jti string, now time.Time, duration time.Duration) (string, error) {
	if secret == "" {
		return "", errors.New("jwt secret is required")
	}

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claims := JWTClaims{
		Subject:   userID,
		JTI:       jti,
		Issuer:    "topchoicebank",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(duration).Unix(),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := fmt.Sprintf("%s.%s", headerB64, claimsB64)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", unsignedToken, signature), nil
}

func VerifyAccessToken(secret string, tokenStr string, now time.Time) (*JWTClaims, error) {
	if secret == "" {
		return nil, errors.New("jwt secret is required")
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	unsignedToken := fmt.Sprintf("%s.%s", parts[0], parts[1])
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(unsignedToken))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, ErrInvalidToken
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if now.Unix() >= claims.ExpiresAt {
		return nil, ErrExpiredToken
	}

	return &claims, nil
}

func HashToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

