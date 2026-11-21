package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
)

// ConsentClaims contains the validated OAuth parameters bundled into a one-time consent token.
type ConsentClaims struct {
	UserID              string    `json:"user_id"`
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	State               string    `json:"state"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// OAuthAdapter coordinates OAuth 2.0 authorization code and S256 PKCE flows using fosite.
type OAuthAdapter struct {
	provider fosite.OAuth2Provider
	store    *PostgresOAuthStore
	secret   []byte
}

// NewOAuthAdapter initializes the constrained partner OAuth 2.0 provider with S256 PKCE enforcement.
func NewOAuthAdapter(db *sql.DB, secret string) *OAuthAdapter {
	secretBytes := []byte(secret)
	if len(secretBytes) < 32 {
		h := sha256.Sum256(secretBytes)
		secretBytes = h[:]
	}

	config := &fosite.Config{
		GlobalSecret:                   secretBytes,
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false, // strictly enforce S256 PKCE
		AuthorizeCodeLifespan:          10 * time.Minute,
		AccessTokenLifespan:            1 * time.Hour,
		RedirectSecureChecker: func(ctx context.Context, u *url.URL) bool {
			return true // allow http/https in dev and test environments
		},
	}

	store := NewPostgresOAuthStore(db)
	strategy := compose.NewOAuth2HMACStrategy(config)

	// Compose ONLY Authorize Code Explicit and PKCE factories.
	// Implicit and Resource Owner Password grants are omitted by design.
	oauth2Provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
	)

	return &OAuthAdapter{
		provider: oauth2Provider,
		store:    store,
		secret:   secretBytes,
	}
}

// Store returns the underlying PostgresOAuthStore.
func (a *OAuthAdapter) Store() *PostgresOAuthStore {
	return a.store
}

// Provider returns the configured fosite.OAuth2Provider instance.
func (a *OAuthAdapter) Provider() fosite.OAuth2Provider {
	return a.provider
}

// GenerateConsentToken generates a cryptographically signed consent token for the authorization request.
func (a *OAuthAdapter) GenerateConsentToken(
	userID, clientID, redirectURI string,
	scopes []string,
	state, codeChallenge, codeChallengeMethod string,
) (string, error) {
	claims := ConsentClaims{
		UserID:              userID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute),
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal consent claims: %w", err)
	}

	payloadBase64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payloadBase64))
	sigBase64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", payloadBase64, sigBase64), nil
}

// ValidateConsentToken verifies the signature and expiration of a consent token.
func (a *OAuthAdapter) ValidateConsentToken(tokenStr string) (*ConsentClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid consent token format")
	}

	payloadBase64, sigBase64 := parts[0], parts[1]

	expectedMAC := hmac.New(sha256.New, a.secret)
	expectedMAC.Write([]byte(payloadBase64))
	expectedSig := expectedMAC.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return nil, errors.New("invalid consent token signature encoding")
	}

	if !hmac.Equal(actualSig, expectedSig) {
		return nil, errors.New("invalid consent token signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, errors.New("invalid consent token payload encoding")
	}

	var claims ConsentClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode consent claims: %w", err)
	}

	if time.Now().UTC().After(claims.ExpiresAt) {
		return nil, errors.New("consent token has expired")
	}

	return &claims, nil
}

// NewSession creates a standard fosite session with the specified subject (user ID).
func (a *OAuthAdapter) NewSession(userID string) fosite.Session {
	return &openid.DefaultSession{
		Subject: userID,
	}
}
