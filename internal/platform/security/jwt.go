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
	Subject   string   `json:"sub"`
	JTI       string   `json:"jti"`
	Issuer    string   `json:"iss"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	Roles     []string `json:"roles,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	AMR       []string `json:"amr,omitempty"`
	AuthTime  int64    `json:"auth_time,omitempty"`
}

type TokenPair struct {
	AccessToken  string
	ExpiresIn    int
	RefreshToken string
	SessionID    string
}

// GenerateAccessToken creates an HMAC-SHA256 access token for a user.
func GenerateAccessToken(secret string, userID string, jti string, now time.Time, duration time.Duration) (string, error) {
	claims := JWTClaims{
		Subject:   userID,
		JTI:       jti,
		Issuer:    "topchoicebank",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(duration).Unix(),
	}
	return GenerateAccessTokenWithClaims(secret, claims)
}

// GenerateAccessTokenWithClaims creates an HMAC-SHA256 access token with full claims.
func GenerateAccessTokenWithClaims(secret string, claims JWTClaims) (string, error) {
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

	if claims.Issuer == "" {
		claims.Issuer = "topchoicebank"
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

// VerifyAccessToken validates an access token's signature, algorithm, claims, and expiration.
func VerifyAccessToken(secret string, tokenStr string, now time.Time) (*JWTClaims, error) {
	if secret == "" {
		return nil, errors.New("jwt secret is required")
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "HS256" {
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

	if strings.TrimSpace(claims.Subject) == "" {
		return nil, ErrInvalidToken
	}

	if claims.ExpiresAt <= 0 || now.Unix() >= claims.ExpiresAt {
		return nil, ErrExpiredToken
	}

	if claims.Issuer != "" && claims.Issuer != "topchoicebank" {
		return nil, ErrInvalidToken
	}

	return &claims, nil
}

// HashToken returns the SHA-256 digest of token.
func HashToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}
