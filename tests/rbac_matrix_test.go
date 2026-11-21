package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Davysongs/TopChoiceBank/internal/identity/domain"
	platformhttp "github.com/Davysongs/TopChoiceBank/internal/platform/http"
	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
)

// buildTokenWithRole generates a valid JWT access token for a given user ID, roles, and AMR claims.
func buildTokenWithRole(t *testing.T, secret string, userID string, roles []string, amr []string, authTime time.Time) string {
	t.Helper()
	now := time.Now().UTC()
	scopes := domain.DefaultScopesForRoles(roles)
	claims := security.JWTClaims{
		Subject:   userID,
		JTI:       uuid.New().String(),
		Issuer:    "topchoicebank",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		Roles:     roles,
		Scopes:    scopes,
		AMR:       amr,
		AuthTime:  authTime.Unix(),
	}
	token, err := security.GenerateAccessTokenWithClaims(secret, claims)
	if err != nil {
		t.Fatalf("failed to generate access token: %v", err)
	}
	return token
}

// setupRBACMatrixRouter sets up a router with sample endpoints representing customer, admin, risk, and read-only routes.
func setupRBACMatrixRouter(secret string) http.Handler {
	mux := http.NewServeMux()

	wrap := func(handler http.Handler, middlewares ...platformhttp.Middleware) http.Handler {
		h := handler
		for i := len(middlewares) - 1; i >= 0; i-- {
			h = middlewares[i](h)
		}
		return h
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// 1. Profile Read: customer, admin, readonly
	mux.Handle("/v1/profile", wrap(okHandler,
		platformhttp.RequireAuth(secret),
		platformhttp.RequireRoles(domain.RoleCustomer, domain.RoleAdmin, domain.RoleReadonly),
		platformhttp.RequireScopes(domain.ScopeProfileRead),
	))

	// 2. Profile Write: customer, admin
	mux.Handle("/v1/profile/edit", wrap(okHandler,
		platformhttp.RequireAuth(secret),
		platformhttp.RequireRoles(domain.RoleCustomer, domain.RoleAdmin),
		platformhttp.RequireScopes(domain.ScopeProfileWrite),
	))

	// 3. Admin fee configuration: admin only
	mux.Handle("/v1/admin/fees", wrap(okHandler,
		platformhttp.RequireAuth(secret),
		platformhttp.RequireRoles(domain.RoleAdmin),
		platformhttp.RequireScopes(domain.ScopeFeesAdmin),
	))

	// 4. KYC Review: admin, risk_analyst
	mux.Handle("/v1/admin/kyc/cases", wrap(okHandler,
		platformhttp.RequireAuth(secret),
		platformhttp.RequireRoles(domain.RoleAdmin, domain.RoleRiskAnalyst),
		platformhttp.RequireScopes(domain.ScopeKYCReview),
	))

	// 5. Sensitive administrative mutation requiring recent MFA: admin only with recent MFA
	mux.Handle("/v1/admin/transfer/reverse", wrap(okHandler,
		platformhttp.RequireAuth(secret),
		platformhttp.RequireRoles(domain.RoleAdmin),
		platformhttp.RequireScopes(domain.ScopeTransfersReverse),
		platformhttp.RequireRecentMFA(15*time.Minute),
	))

	return mux
}

// TestRBACMatrixAcrossAllFourRoles tests all four roles (customer, admin, risk_analyst, readonly)
// across customer, administrative, and risk endpoints for allow/deny enforcement.
func TestRBACMatrixAcrossAllFourRoles(t *testing.T) {
	jwtSecret := "matrix-test-jwt-secret-key-32bytes!!"
	handler := setupRBACMatrixRouter(jwtSecret)
	server := httptest.NewServer(handler)
	defer server.Close()

	now := time.Now().UTC()
	userA := uuid.New().String()

	customerToken := buildTokenWithRole(t, jwtSecret, userA, []string{domain.RoleCustomer}, []string{"pwd"}, now)
	adminToken := buildTokenWithRole(t, jwtSecret, userA, []string{domain.RoleAdmin}, []string{"pwd", "mfa"}, now)
	riskToken := buildTokenWithRole(t, jwtSecret, userA, []string{domain.RoleRiskAnalyst}, []string{"pwd"}, now)
	readonlyToken := buildTokenWithRole(t, jwtSecret, userA, []string{domain.RoleReadonly}, []string{"pwd"}, now)

	type testCase struct {
		endpoint       string
		roleName       string
		token          string
		expectedStatus int
	}

	tests := []testCase{
		// /v1/profile (profile:read) -> customer (200), admin (200), risk_analyst (403), readonly (200)
		{"/v1/profile", "customer", customerToken, http.StatusOK},
		{"/v1/profile", "admin", adminToken, http.StatusOK},
		{"/v1/profile", "risk_analyst", riskToken, http.StatusForbidden},
		{"/v1/profile", "readonly", readonlyToken, http.StatusOK},

		// /v1/profile/edit (profile:write) -> customer (200), admin (200), risk_analyst (403), readonly (403)
		{"/v1/profile/edit", "customer", customerToken, http.StatusOK},
		{"/v1/profile/edit", "admin", adminToken, http.StatusOK},
		{"/v1/profile/edit", "risk_analyst", riskToken, http.StatusForbidden},
		{"/v1/profile/edit", "readonly", readonlyToken, http.StatusForbidden},

		// /v1/admin/fees (fees:admin) -> customer (403), admin (200), risk_analyst (403), readonly (403)
		{"/v1/admin/fees", "customer", customerToken, http.StatusForbidden},
		{"/v1/admin/fees", "admin", adminToken, http.StatusOK},
		{"/v1/admin/fees", "risk_analyst", riskToken, http.StatusForbidden},
		{"/v1/admin/fees", "readonly", readonlyToken, http.StatusForbidden},

		// /v1/admin/kyc/cases (kyc:review) -> customer (403), admin (200), risk_analyst (200), readonly (403)
		{"/v1/admin/kyc/cases", "customer", customerToken, http.StatusForbidden},
		{"/v1/admin/kyc/cases", "admin", adminToken, http.StatusOK},
		{"/v1/admin/kyc/cases", "risk_analyst", riskToken, http.StatusOK},
		{"/v1/admin/kyc/cases", "readonly", readonlyToken, http.StatusForbidden},
	}

	for _, tc := range tests {
		req, _ := http.NewRequest(http.MethodGet, server.URL+tc.endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed request %s for %s: %v", tc.endpoint, tc.roleName, err)
		}
		if resp.StatusCode != tc.expectedStatus {
			t.Errorf("endpoint %s for role %s: expected status %d, got %d", tc.endpoint, tc.roleName, tc.expectedStatus, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Verify allowed role lacking required scope returns 403 Forbidden
	noWriteScopeToken, err := security.GenerateAccessTokenWithClaims(jwtSecret, security.JWTClaims{
		Subject:   userA,
		JTI:       uuid.New().String(),
		Issuer:    "topchoicebank",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		Roles:     []string{domain.RoleCustomer},
		Scopes:    []string{domain.ScopeProfileRead},
		AMR:       []string{"pwd"},
		AuthTime:  now.Unix(),
	})
	if err != nil {
		t.Fatalf("failed to generate no-write token: %v", err)
	}

	reqScopeDenied, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/profile/edit", nil)
	reqScopeDenied.Header.Set("Authorization", "Bearer "+noWriteScopeToken)
	respScopeDenied, err := http.DefaultClient.Do(reqScopeDenied)
	if err != nil {
		t.Fatalf("failed request: %v", err)
	}
	defer respScopeDenied.Body.Close()
	if respScopeDenied.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for allowed role with missing scope, got %d", respScopeDenied.StatusCode)
	}
}

// TestRecentMFAMiddlewareEnforcement tests gating behind recent MFA verification and rejection on expired or missing MFA claims.
func TestRecentMFAMiddlewareEnforcement(t *testing.T) {
	jwtSecret := "matrix-test-jwt-secret-key-32bytes!!"
	handler := setupRBACMatrixRouter(jwtSecret)
	server := httptest.NewServer(handler)
	defer server.Close()

	userID := uuid.New().String()
	now := time.Now().UTC()

	// 1. Admin without MFA in AMR claims -> 403 Forbidden
	noMFAToken := buildTokenWithRole(t, jwtSecret, userID, []string{domain.RoleAdmin}, []string{"pwd"}, now)
	req1, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/admin/transfer/reverse", nil)
	req1.Header.Set("Authorization", "Bearer "+noMFAToken)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for admin without MFA, got %d", resp1.StatusCode)
	}

	// 2. Admin with MFA but expired auth_time (30 minutes ago) -> 403 Forbidden
	staleAuthTime := now.Add(-30 * time.Minute)
	staleMFAToken := buildTokenWithRole(t, jwtSecret, userID, []string{domain.RoleAdmin}, []string{"pwd", "mfa"}, staleAuthTime)
	req2, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/admin/transfer/reverse", nil)
	req2.Header.Set("Authorization", "Bearer "+staleMFAToken)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for admin with stale MFA, got %d", resp2.StatusCode)
	}

	// 3. Admin with fresh MFA -> 200 OK
	freshMFAToken := buildTokenWithRole(t, jwtSecret, userID, []string{domain.RoleAdmin}, []string{"pwd", "mfa"}, now)
	req3, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/admin/transfer/reverse", nil)
	req3.Header.Set("Authorization", "Bearer "+freshMFAToken)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for admin with fresh MFA, got %d", resp3.StatusCode)
	}
}

// TestObjectLevelOwnershipEnforcement tests application-layer resource ownership checks.
func TestObjectLevelOwnershipEnforcement(t *testing.T) {
	customerA := uuid.New().String()
	customerB := uuid.New().String()

	claimsCustomerA := &security.JWTClaims{
		Subject: customerA,
		Roles:   []string{domain.RoleCustomer},
	}
	claimsAdmin := &security.JWTClaims{
		Subject: uuid.New().String(),
		Roles:   []string{domain.RoleAdmin},
	}

	// Customer A accessing Customer A's resource -> true
	if !platformhttp.CheckResourceOwnership(claimsCustomerA, customerA) {
		t.Error("expected Customer A to own customerA resource")
	}

	// Customer A accessing Customer B's resource -> false
	if platformhttp.CheckResourceOwnership(claimsCustomerA, customerB) {
		t.Error("expected Customer A to NOT own customerB resource")
	}

	// Admin accessing Customer B's resource -> true (administrative override)
	if !platformhttp.CheckResourceOwnership(claimsAdmin, customerB) {
		t.Error("expected Admin to have administrative override for customerB resource")
	}
}
