package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/ory/fosite"
)

// generatePKCEPair creates a random PKCE verifier and its corresponding S256 challenge.
func generatePKCEPair() (string, string) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

// TestOAuthAdapter_PKCEEnforcement verifies that S256 PKCE is enforced and plain method is rejected.
func TestOAuthAdapter_PKCEEnforcement(t *testing.T) {
	adapter := NewOAuthAdapter(nil, "adapter-unit-test-secret-32-bytes!!")
	ctx := context.Background()

	client := &fosite.DefaultClient{
		ID:            "unit-test-client",
		RedirectURIs:  []string{"https://client.example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"accounts:read"},
		Public:        true,
	}
	_ = adapter.Store().RegisterClient(ctx, client, "Unit Test Client")

	_, challenge := generatePKCEPair()

	// 1. Request with plain PKCE challenge method must be rejected
	plainForm := url.Values{
		"client_id":             {"unit-test-client"},
		"redirect_uri":          {"https://client.example.com/cb"},
		"response_type":         {"code"},
		"scope":                 {"accounts:read"},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"plain"},
	}
	plainReq, _ := http.NewRequest(http.MethodGet, "/v1/oauth/authorize?"+plainForm.Encode(), nil)
	plainReq.Form = plainForm

	_, err := adapter.Provider().NewAuthorizeRequest(ctx, plainReq)
	if err == nil {
		t.Fatal("expected error when code_challenge_method is plain")
	}

	// 2. Request with S256 PKCE challenge method must succeed
	s256Form := url.Values{
		"client_id":             {"unit-test-client"},
		"redirect_uri":          {"https://client.example.com/cb"},
		"response_type":         {"code"},
		"scope":                 {"accounts:read"},
		"state":                 {"random-state-xyz-123456"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	s256Req, _ := http.NewRequest(http.MethodGet, "/v1/oauth/authorize?"+s256Form.Encode(), nil)
	s256Req.Form = s256Form

	ar, err := adapter.Provider().NewAuthorizeRequest(ctx, s256Req)
	if err != nil {
		t.Fatalf("expected valid S256 request, got err: %v", err)
	}
	if ar.GetClient().GetID() != "unit-test-client" {
		t.Fatalf("expected client ID unit-test-client, got %s", ar.GetClient().GetID())
	}
}

// TestOAuthAdapter_ExactRedirectURIMatching verifies that redirect URIs must match registered values exactly.
func TestOAuthAdapter_ExactRedirectURIMatching(t *testing.T) {
	adapter := NewOAuthAdapter(nil, "adapter-unit-test-secret-32-bytes!!")
	ctx := context.Background()

	client := &fosite.DefaultClient{
		ID:            "redirect-client",
		RedirectURIs:  []string{"https://client.example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"accounts:read"},
		Public:        true,
	}
	_ = adapter.Store().RegisterClient(ctx, client, "Redirect Test Client")

	_, challenge := generatePKCEPair()

	badForm := url.Values{
		"client_id":             {"redirect-client"},
		"redirect_uri":          {"https://evil.example.com/cb"},
		"response_type":         {"code"},
		"scope":                 {"accounts:read"},
		"state":                 {"random-state-xyz-123456"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	badReq, _ := http.NewRequest(http.MethodGet, "/v1/oauth/authorize?"+badForm.Encode(), nil)
	badReq.Form = badForm

	_, err := adapter.Provider().NewAuthorizeRequest(ctx, badReq)
	if err == nil {
		t.Fatal("expected error for mismatched redirect URI")
	}
}

// TestOAuthAdapter_ConsentTokenLifecycle verifies signing and validation of consent tokens.
func TestOAuthAdapter_ConsentTokenLifecycle(t *testing.T) {
	adapter := NewOAuthAdapter(nil, "adapter-unit-test-secret-32-bytes!!")

	tokenStr, err := adapter.GenerateConsentToken(
		"user-123",
		"partner-client",
		"https://partner.example.com/cb",
		[]string{"accounts:read"},
		"state-abc",
		"challenge-s256",
		"S256",
	)
	if err != nil {
		t.Fatalf("failed to generate consent token: %v", err)
	}

	claims, err := adapter.ValidateConsentToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to validate valid consent token: %v", err)
	}
	if claims.UserID != "user-123" || claims.ClientID != "partner-client" {
		t.Fatalf("claims mismatch: %+v", claims)
	}

	// Tampered token fails
	tampered := tokenStr + "tamper"
	_, err = adapter.ValidateConsentToken(tampered)
	if err == nil {
		t.Fatal("expected error for tampered consent token signature")
	}
}
