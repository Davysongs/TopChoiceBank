package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
	"github.com/Davysongs/TopChoiceBank/internal/identity/adapters/oauth"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	platformhttp "github.com/Davysongs/TopChoiceBank/internal/platform/http"
	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
)

// generateTestPKCE produces a valid verifier and its S256 code challenge.
func generateTestPKCE() (string, string) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-topchoicebank-pkce-verifier-test"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

// setupOAuthTestServer creates a test server with both identity auth and OAuth endpoints registered.
func setupOAuthTestServer(t *testing.T) (*httptest.Server, *oauth.OAuthAdapter, *identity.Service) {
	t.Helper()

	server, db := setupTestServer(t)
	server.Close() // we will use our own router with oauth registered

	migCtx, migCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer migCancel()
	_ = platformdb.ApplyIdentityBootstrapMigrations(migCtx, db)

	logger := logging.New("error")
	router := platformhttp.NewRouter()
	router.Use(platformhttp.RequestIDMiddleware())
	router.Use(platformhttp.RequestLoggerMiddleware(logger))

	jwtSecret := "integration-test-jwt-secret-key-32bytes"
	repo := identity.NewPostgresRepository(db)
	svc := identity.NewService(repo, jwtSecret)
	platformhttp.RegisterAuthRoutes(router, svc)

	adapter := oauth.NewOAuthAdapter(db, jwtSecret)
	platformhttp.RegisterOAuthRoutes(router, adapter, jwtSecret)

	oauthServer := httptest.NewServer(router.Handler())
	return oauthServer, adapter, svc
}

// TestOAuth2_S256PKCE_CodeExchangeAndReplayPrevention tests the complete PKCE code flow,
// exact redirect matching, and single-use authorization code enforcement.
func TestOAuth2_S256PKCE_CodeExchangeAndReplayPrevention(t *testing.T) {
	server, adapter, _ := setupOAuthTestServer(t)
	defer server.Close()

	// 1. Register a public partner client in PostgreSQL
	clientID := "fintech-partner-app"
	redirectURI := "https://partner.example.com/oauth/callback"
	client := &fosite.DefaultClient{
		ID:            clientID,
		RedirectURIs:  []string{redirectURI},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"accounts:read", "transfers:read"},
		Public:        true,
	}
	if err := adapter.Store().RegisterClient(context.Background(), client, "Fintech Partner App"); err != nil {
		t.Fatalf("failed to register oauth client: %v", err)
	}

	// 2. Register and log in a customer to obtain a Bearer access token
	_, _, _, userToken := registerAndLoginHelper(t, server.URL)

	verifier, challenge := generateTestPKCE()
	state := "random-state-12345"

	// 3. Initiate authorization request (GET /v1/oauth/authorize)
	authParams := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"accounts:read"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	reqAuth, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/oauth/authorize?"+authParams.Encode(), nil)
	reqAuth.Header.Set("Authorization", "Bearer "+userToken)

	respAuth, err := http.DefaultClient.Do(reqAuth)
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	defer respAuth.Body.Close()

	if respAuth.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(respAuth.Body)
		t.Fatalf("expected 200 OK from authorize get, got %d: %s", respAuth.StatusCode, buf.String())
	}

	var consentData struct {
		ClientName      string   `json:"client_name"`
		RequestedScopes []string `json:"requested_scopes"`
		ConsentToken    string   `json:"consent_token"`
	}
	if err := json.NewDecoder(respAuth.Body).Decode(&consentData); err != nil {
		t.Fatalf("failed to decode consent data: %v", err)
	}

	if consentData.ConsentToken == "" {
		t.Fatal("expected non-empty consent_token")
	}

	// 4. Submit consent (POST /v1/oauth/authorize) without following redirects automatically
	consentPayload, _ := json.Marshal(map[string]any{
		"consent_token": consentData.ConsentToken,
		"approved":      true,
	})

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	respConsent, err := noRedirectClient.Post(
		server.URL+"/v1/oauth/authorize",
		"application/json",
		bytes.NewBuffer(consentPayload),
	)
	if err != nil {
		t.Fatalf("failed to post consent: %v", err)
	}
	defer respConsent.Body.Close()

	if respConsent.StatusCode != http.StatusFound && respConsent.StatusCode != http.StatusSeeOther {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(respConsent.Body)
		t.Fatalf("expected 302 or 303 redirect after consent, got %d: %s", respConsent.StatusCode, buf.String())
	}

	locationURL := respConsent.Header.Get("Location")
	if locationURL == "" {
		t.Fatal("expected Location header in consent response")
	}

	parsedLoc, err := url.Parse(locationURL)
	if err != nil {
		t.Fatalf("failed to parse redirect location: %v", err)
	}

	authCode := parsedLoc.Query().Get("code")
	if authCode == "" {
		t.Fatalf("expected code query param in redirect URL: %s", locationURL)
	}
	if parsedLoc.Query().Get("state") != state {
		t.Fatalf("expected state %s, got %s", state, parsedLoc.Query().Get("state"))
	}

	// 5. Exchange code for tokens (POST /v1/oauth/token)
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}

	respToken, err := http.PostForm(server.URL+"/v1/oauth/token", tokenParams)
	if err != nil {
		t.Fatalf("token exchange request failed: %v", err)
	}
	defer respToken.Body.Close()

	if respToken.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(respToken.Body)
		t.Fatalf("expected 200 OK from token exchange, got %d: %s", respToken.StatusCode, buf.String())
	}

	var tokenData struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(respToken.Body).Decode(&tokenData); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokenData.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if !strings.EqualFold(tokenData.TokenType, "bearer") {
		t.Fatalf("expected token_type bearer (case-insensitive), got %s", tokenData.TokenType)
	}

	// 6. Single-use authorization code enforcement: Replaying the code must fail
	replayResp, err := http.PostForm(server.URL+"/v1/oauth/token", tokenParams)
	if err != nil {
		t.Fatalf("replay token exchange request failed: %v", err)
	}
	defer replayResp.Body.Close()

	if replayResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on code reuse, got %d", replayResp.StatusCode)
	}
}

// TestOAuth2_SecurityRejections verifies PKCE method enforcement, exact redirect URI matching,
// and invalid verifier rejection.
func TestOAuth2_SecurityRejections(t *testing.T) {
	server, adapter, _ := setupOAuthTestServer(t)
	defer server.Close()

	clientID := "security-test-client"
	validRedirectURI := "https://partner.example.com/oauth/callback"
	client := &fosite.DefaultClient{
		ID:            clientID,
		RedirectURIs:  []string{validRedirectURI},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"accounts:read"},
		Public:        true,
	}
	_ = adapter.Store().RegisterClient(context.Background(), client, "Security Test Client")

	_, _, _, userToken := registerAndLoginHelper(t, server.URL)
	verifier, challenge := generateTestPKCE()

	// 1. Plain PKCE challenge method rejected
	plainParams := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {validRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"accounts:read"},
		"state":                 {"random-state-12345"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"plain"},
	}
	reqPlain, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/oauth/authorize?"+plainParams.Encode(), nil)
	reqPlain.Header.Set("Authorization", "Bearer "+userToken)
	respPlain, err := http.DefaultClient.Do(reqPlain)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer respPlain.Body.Close()
	if respPlain.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for plain PKCE method, got %d", respPlain.StatusCode)
	}

	// 2. Mismatched redirect_uri rejected
	mismatchParams := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"https://evil.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"accounts:read"},
		"state":                 {"random-state-12345"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	reqMismatch, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/oauth/authorize?"+mismatchParams.Encode(), nil)
	reqMismatch.Header.Set("Authorization", "Bearer "+userToken)
	respMismatch, err := http.DefaultClient.Do(reqMismatch)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer respMismatch.Body.Close()
	if respMismatch.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for mismatched redirect_uri, got %d", respMismatch.StatusCode)
	}

	// 3. Unknown client rejected
	unknownClientParams := url.Values{
		"client_id":             {"unknown-client"},
		"redirect_uri":          {validRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"accounts:read"},
		"state":                 {"random-state-12345"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	reqUnknown, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/oauth/authorize?"+unknownClientParams.Encode(), nil)
	reqUnknown.Header.Set("Authorization", "Bearer "+userToken)
	respUnknown, err := http.DefaultClient.Do(reqUnknown)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer respUnknown.Body.Close()
	if respUnknown.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for unknown client, got %d", respUnknown.StatusCode)
	}

	// 4. Code exchange with invalid PKCE verifier rejected
	autoApproveParams := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {validRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"accounts:read"},
		"state":                 {"state123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"consent":               {"approve"},
	}
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	reqAuto, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/oauth/authorize?"+autoApproveParams.Encode(), nil)
	reqAuto.Header.Set("Authorization", "Bearer "+userToken)
	respAuto, err := noRedirectClient.Do(reqAuto)
	if err != nil {
		t.Fatalf("auto-consent request failed: %v", err)
	}
	defer respAuto.Body.Close()

	loc, _ := url.Parse(respAuto.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected code from auto-consent")
	}

	badVerifierParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {validRedirectURI},
		"client_id":     {clientID},
		"code_verifier": {"wrong-verifier-123456789012345678901234567890"},
	}
	respBadVerifier, err := http.PostForm(server.URL+"/v1/oauth/token", badVerifierParams)
	if err != nil {
		t.Fatalf("bad verifier exchange failed: %v", err)
	}
	defer respBadVerifier.Body.Close()

	if respBadVerifier.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid code_verifier, got %d", respBadVerifier.StatusCode)
	}

	// 5. Code exchange with valid PKCE verifier succeeds (using a fresh authorization code)
	reqAutoValid, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/oauth/authorize?"+autoApproveParams.Encode(), nil)
	reqAutoValid.Header.Set("Authorization", "Bearer "+userToken)
	respAutoValid, err := noRedirectClient.Do(reqAutoValid)
	if err != nil {
		t.Fatalf("auto-consent request for valid code failed: %v", err)
	}
	defer respAutoValid.Body.Close()

	locValid, _ := url.Parse(respAutoValid.Header.Get("Location"))
	validCode := locValid.Query().Get("code")
	if validCode == "" {
		t.Fatal("expected validCode from auto-consent")
	}

	goodVerifierParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {validCode},
		"redirect_uri":  {validRedirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	respGoodVerifier, err := http.PostForm(server.URL+"/v1/oauth/token", goodVerifierParams)
	if err != nil {
		t.Fatalf("good verifier exchange failed: %v", err)
	}
	defer respGoodVerifier.Body.Close()

	if respGoodVerifier.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(respGoodVerifier.Body)
		t.Fatalf("expected 200 OK for valid code_verifier, got %d: %s", respGoodVerifier.StatusCode, buf.String())
	}
}
