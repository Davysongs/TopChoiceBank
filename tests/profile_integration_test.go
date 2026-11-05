package tests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	platformhttp "github.com/Davysongs/TopChoiceBank/internal/platform/http"
	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
	"github.com/Davysongs/TopChoiceBank/internal/users"
)

const testJWTSecret = "integration-test-jwt-secret-key-32bytes"

var phoneCounter int64

// uniquePhone generates a monotonically increasing unique E.164 phone number for testing.
func uniquePhone() string {
	val := atomic.AddInt64(&phoneCounter, 1)
	return fmt.Sprintf("+1%010d%04d", time.Now().Unix(), val%10000)
}

// setupProfileTestServer creates a migrated test database and HTTP server configured with profile and auth routes.
func setupProfileTestServer(t *testing.T) (*httptest.Server, *sql.DB, *users.Service) {
	t.Helper()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://topchoicebank:topchoicebank@localhost:5432/topchoicebank?sslmode=disable"
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("skipping integration test: failed to open postgres connection: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Skipf("skipping integration test: database unpingable: %v", err)
	}

	migCtx, migCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer migCancel()

	if err := platformdb.ApplyIdentityBootstrapMigrations(migCtx, db); err != nil {
		t.Fatalf("failed to apply migrations: %v", err)
	}

	logger := logging.New("error")
	router := platformhttp.NewRouter()
	router.Use(platformhttp.RequestIDMiddleware())
	router.Use(platformhttp.RequestLoggerMiddleware(logger))

	identityRepo := identity.NewPostgresRepository(db)
	identitySvc := identity.NewService(identityRepo, testJWTSecret)
	platformhttp.RegisterAuthRoutes(router, identitySvc)

	usersRepo := users.NewPostgresRepository(db)
	usersSvc := users.NewService(usersRepo, identityRepo)
	platformhttp.RegisterUserRoutes(router, usersSvc, testJWTSecret)

	server := httptest.NewServer(router.Handler())
	return server, db, usersSvc
}

// registerAndLoginUser registers a new user with the given email and returns the user ID and access token.
func registerAndLoginUser(t *testing.T, server *httptest.Server, email string) (string, string) {
	t.Helper()

	regBody, _ := json.Marshal(map[string]any{
		"email":                  email,
		"password":               "P@ssword1234!",
		"accepted_terms_version": "v1.0",
	})

	regResp, err := http.Post(server.URL+"/v1/auth/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created for registration, got %d", regResp.StatusCode)
	}

	var regData map[string]any
	_ = json.NewDecoder(regResp.Body).Decode(&regData)
	userID := regData["user_id"].(string)

	loginBody, _ := json.Marshal(map[string]any{
		"email":              email,
		"password":           "P@ssword1234!",
		"device_fingerprint": "device-fp-" + email,
	})

	loginResp, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("failed to login user: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for login, got %d", loginResp.StatusCode)
	}

	var loginData map[string]any
	_ = json.NewDecoder(loginResp.Body).Decode(&loginData)
	token := loginData["access_token"].(string)

	return userID, token
}

// TestProfile_CreateAndGetProfile verifies profile creation and subsequent retrieval with masked PII and ETag headers.
func TestProfile_CreateAndGetProfile(t *testing.T) {
	server, db, usersSvc := setupProfileTestServer(t)
	defer server.Close()
	defer db.Close()

	email := fmt.Sprintf("alice_%d@example.com", time.Now().UnixNano())
	userID, token := registerAndLoginUser(t, server, email)

	// Create profile for user
	_, err := usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userID,
		LegalGivenName:  "Alice",
		LegalFamilyName: "Smith",
		DateOfBirth:     "1992-05-14",
		PhoneE164:       uniquePhone(),
		Address: users.AddressInput{
			Line1:       "123 Wall Street",
			Line2:       "Suite 400",
			City:        "New York",
			Region:      "NY",
			PostalCode:  "10005",
			CountryCode: "US",
		},
	})
	if err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// GET /v1/users/me
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/users/me failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")
	if etag != "\"1\"" {
		t.Errorf("expected ETag \"1\", got %q", etag)
	}

	var prof users.ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&prof); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if prof.ID != userID {
		t.Errorf("expected id %s, got %s", userID, prof.ID)
	}
	if prof.LegalName != "Alice Smith" {
		t.Errorf("expected legal_name 'Alice Smith', got %q", prof.LegalName)
	}
	if !strings.HasPrefix(prof.PhoneMasked, "+1*") {
		t.Errorf("expected masked phone, got %q", prof.PhoneMasked)
	}
	if prof.OnboardingState != "PENDING" {
		t.Errorf("expected onboarding_state 'PENDING', got %q", prof.OnboardingState)
	}
	if prof.Version != 1 {
		t.Errorf("expected version 1, got %d", prof.Version)
	}
	if prof.Address.City != "New York" || prof.Address.CountryCode != "US" {
		t.Errorf("unexpected address: %+v", prof.Address)
	}
}

// TestProfile_CrossTenantAccessDenied verifies that a user cannot access or mutate another customer's profile.
func TestProfile_CrossTenantAccessDenied(t *testing.T) {
	server, db, usersSvc := setupProfileTestServer(t)
	defer server.Close()
	defer db.Close()

	emailA := fmt.Sprintf("tenant_a_%d@example.com", time.Now().UnixNano())
	userIDA, tokenA := registerAndLoginUser(t, server, emailA)

	emailB := fmt.Sprintf("tenant_b_%d@example.com", time.Now().UnixNano())
	userIDB, tokenB := registerAndLoginUser(t, server, emailB)

	phoneA := uniquePhone()
	_, err := usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userIDA,
		LegalGivenName:  "User",
		LegalFamilyName: "Alpha",
		DateOfBirth:     "1990-01-01",
		PhoneE164:       phoneA,
		Address: users.AddressInput{
			Line1:       "1 Alpha Way",
			City:        "Boston",
			CountryCode: "US",
		},
	})
	if err != nil {
		t.Fatalf("failed to create profile A: %v", err)
	}

	phoneB := uniquePhone()
	_, err = usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userIDB,
		LegalGivenName:  "User",
		LegalFamilyName: "Beta",
		DateOfBirth:     "1991-02-02",
		PhoneE164:       phoneB,
		Address: users.AddressInput{
			Line1:       "2 Beta Ave",
			City:        "Chicago",
			CountryCode: "US",
		},
	})
	if err != nil {
		t.Fatalf("failed to create profile B: %v", err)
	}

	// User B queries /v1/users/me: must only see User B's profile
	reqB, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/users/me", nil)
	reqB.Header.Set("Authorization", "Bearer "+tokenB)
	respB, err := http.DefaultClient.Do(reqB)
	if err != nil {
		t.Fatalf("failed GET /v1/users/me for user B: %v", err)
	}
	defer respB.Body.Close()

	var dataB users.ProfileResponse
	_ = json.NewDecoder(respB.Body).Decode(&dataB)
	if dataB.ID != userIDB || dataB.LegalName != "User Beta" {
		t.Errorf("User B saw wrong profile data: %+v", dataB)
	}

	// User B patches their own profile
	newPhoneB := uniquePhone()
	patchBody, _ := json.Marshal(map[string]any{
		"phone_e164": newPhoneB,
	})
	patchReqB, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader(patchBody))
	patchReqB.Header.Set("Authorization", "Bearer "+tokenB)
	patchReqB.Header.Set("If-Match", "\"1\"")
	patchReqB.Header.Set("Content-Type", "application/json")

	patchRespB, err := http.DefaultClient.Do(patchReqB)
	if err != nil {
		t.Fatalf("patch request failed: %v", err)
	}
	defer patchRespB.Body.Close()

	if patchRespB.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for patch, got %d", patchRespB.StatusCode)
	}

	// Verify User A's profile is completely unchanged
	reqA, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/users/me", nil)
	reqA.Header.Set("Authorization", "Bearer "+tokenA)
	respA, err := http.DefaultClient.Do(reqA)
	if err != nil {
		t.Fatalf("failed GET /v1/users/me for user A: %v", err)
	}
	defer respA.Body.Close()

	var dataA users.ProfileResponse
	_ = json.NewDecoder(respA.Body).Decode(&dataA)
	if dataA.ID != userIDA || dataA.LegalName != "User Alpha" || dataA.Version != 1 {
		t.Errorf("User A's profile was altered by User B: %+v", dataA)
	}
}

// TestProfile_PatchOptimisticConcurrency tests If-Match optimistic locking, version increments, and conflict rejection on stale versions.
func TestProfile_PatchOptimisticConcurrency(t *testing.T) {
	server, db, usersSvc := setupProfileTestServer(t)
	defer server.Close()
	defer db.Close()

	email := fmt.Sprintf("concur_%d@example.com", time.Now().UnixNano())
	userID, token := registerAndLoginUser(t, server, email)

	phone := uniquePhone()
	_, err := usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userID,
		LegalGivenName:  "Optimistic",
		LegalFamilyName: "Tester",
		DateOfBirth:     "1988-08-08",
		PhoneE164:       phone,
		Address: users.AddressInput{
			Line1:       "100 Broadway",
			City:        "New York",
			CountryCode: "US",
		},
	})
	if err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Step 1: Patch with matching If-Match: "1" -> should succeed
	newPhone1 := uniquePhone()
	patchBody1, _ := json.Marshal(map[string]any{
		"phone_e164": newPhone1,
	})
	req1, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader(patchBody1))
	req1.Header.Set("Authorization", "Bearer "+token)
	req1.Header.Set("If-Match", "\"1\"")
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("patch 1 failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on first patch, got %d", resp1.StatusCode)
	}
	if resp1.Header.Get("ETag") != "\"2\"" {
		t.Errorf("expected ETag \"2\", got %q", resp1.Header.Get("ETag"))
	}

	// Step 2: Patch with stale If-Match: "1" -> should return 409 Conflict
	newPhone2 := uniquePhone()
	patchBody2, _ := json.Marshal(map[string]any{
		"phone_e164": newPhone2,
	})
	req2, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader(patchBody2))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("If-Match", "\"1\"") // Stale version!
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("patch 2 failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on stale version patch, got %d", resp2.StatusCode)
	}

	var prob platformhttp.ProblemDetails
	_ = json.NewDecoder(resp2.Body).Decode(&prob)
	if prob.Status != 409 || prob.Title != "Version Conflict" {
		t.Errorf("unexpected problem details: %+v", prob)
	}

	// Step 3: Patch with current If-Match: "2" -> should succeed and advance to version 3
	req3, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader(patchBody2))
	req3.Header.Set("Authorization", "Bearer "+token)
	req3.Header.Set("If-Match", "\"2\"") // Current version!
	req3.Header.Set("Content-Type", "application/json")

	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("patch 3 failed: %v", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on current version patch, got %d", resp3.StatusCode)
	}
	if resp3.Header.Get("ETag") != "\"3\"" {
		t.Errorf("expected ETag \"3\", got %q", resp3.Header.Get("ETag"))
	}

	// Step 4: No-op patch with stale If-Match: "2" -> should return 409 Conflict
	noopReqStale, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader([]byte("{}")))
	noopReqStale.Header.Set("Authorization", "Bearer "+token)
	noopReqStale.Header.Set("If-Match", "\"2\"") // Stale version!
	noopReqStale.Header.Set("Content-Type", "application/json")

	noopRespStale, err := http.DefaultClient.Do(noopReqStale)
	if err != nil {
		t.Fatalf("noop patch stale failed: %v", err)
	}
	defer noopRespStale.Body.Close()

	if noopRespStale.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on stale no-op patch, got %d", noopRespStale.StatusCode)
	}

	// Step 5: No-op patch with matching If-Match: "3" -> should succeed (200 OK) and retain version 3
	noopReqMatch, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader([]byte("{}")))
	noopReqMatch.Header.Set("Authorization", "Bearer "+token)
	noopReqMatch.Header.Set("If-Match", "\"3\"") // Current version!
	noopReqMatch.Header.Set("Content-Type", "application/json")

	noopRespMatch, err := http.DefaultClient.Do(noopReqMatch)
	if err != nil {
		t.Fatalf("noop patch matching failed: %v", err)
	}
	defer noopRespMatch.Body.Close()

	if noopRespMatch.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on matching no-op patch, got %d", noopRespMatch.StatusCode)
	}
	if noopRespMatch.Header.Get("ETag") != "\"3\"" {
		t.Errorf("expected ETag \"3\", got %q", noopRespMatch.Header.Get("ETag"))
	}
}

// TestProfile_InvariantValidationErrors tests validation rules for future birth dates, missing headers, immutable fields, and malformed phone numbers.
func TestProfile_InvariantValidationErrors(t *testing.T) {
	server, db, usersSvc := setupProfileTestServer(t)
	defer server.Close()
	defer db.Close()

	email := fmt.Sprintf("invariants_%d@example.com", time.Now().UnixNano())
	userID, token := registerAndLoginUser(t, server, email)

	phone := uniquePhone()
	_, err := usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userID,
		LegalGivenName:  "Jane",
		LegalFamilyName: "Doe",
		DateOfBirth:     "1994-04-04",
		PhoneE164:       phone,
		Address: users.AddressInput{
			Line1:       "500 Pine St",
			City:        "Seattle",
			CountryCode: "US",
		},
	})
	if err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	t.Run("future date of birth rejected", func(t *testing.T) {
		tomorrow := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02")
		_, err := usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
			UserID:          "dummy-user-id",
			LegalGivenName:  "Future",
			LegalFamilyName: "Child",
			DateOfBirth:     tomorrow,
			PhoneE164:       "+12025550199",
			Address: users.AddressInput{
				Line1:       "1 Future Lane",
				City:        "Seattle",
				CountryCode: "US",
			},
		})
		if err == nil {
			t.Fatal("expected error for future date of birth, got nil")
		}
		if !strings.Contains(err.Error(), "future") {
			t.Errorf("expected future date error, got: %v", err)
		}
	})

	t.Run("missing If-Match header returns 400", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"phone_e164": "+12025550123"})
		req, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", resp.StatusCode)
		}
	})

	t.Run("modifying immutable legal_name returns 403", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"legal_name": "Tampered Name",
			"phone_e164": "+12025550123",
		})
		req, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("If-Match", "\"1\"")
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for immutable legal_name, got %d", resp.StatusCode)
		}
	})

	t.Run("malformed phone number returns 422", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"phone_e164": "not-e164-phone",
		})
		req, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("If-Match", "\"1\"")
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("expected 422 Unprocessable Entity, got %d", resp.StatusCode)
		}

		var prob platformhttp.ProblemDetails
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		if prob.Status != 422 || !strings.Contains(strings.ToLower(prob.Detail), "phone") {
			t.Errorf("expected RFC 9457 detail about phone, got: %+v", prob)
		}
	})
}

// TestProfile_AtomicOutboxEventEmission verifies atomic emission of profile_created and profile_updated events into the outbox table.
func TestProfile_AtomicOutboxEventEmission(t *testing.T) {
	server, db, usersSvc := setupProfileTestServer(t)
	defer server.Close()
	defer db.Close()

	email := fmt.Sprintf("outbox_prof_%d@example.com", time.Now().UnixNano())
	userID, token := registerAndLoginUser(t, server, email)

	phone := uniquePhone()
	_, err := usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userID,
		LegalGivenName:  "Outbox",
		LegalFamilyName: "User",
		DateOfBirth:     "1990-10-10",
		PhoneE164:       phone,
		Address: users.AddressInput{
			Line1:       "10 Outbox St",
			City:        "Denver",
			CountryCode: "US",
		},
	})
	if err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Verify users.profile_created.v1 is in events.outbox_events
	var createdCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM events.outbox_events
		WHERE aggregate_type = 'users.user_profiles'
		  AND aggregate_id = $1
		  AND aggregate_version = 1
		  AND event_type = 'users.profile_created.v1'
	`, userID).Scan(&createdCount)
	if err != nil {
		t.Fatalf("failed to query outbox for created event: %v", err)
	}
	if createdCount != 1 {
		t.Errorf("expected 1 users.profile_created.v1 event, got %d", createdCount)
	}

	// Now patch the profile
	newPhone := uniquePhone()
	patchBody, _ := json.Marshal(map[string]any{
		"phone_e164": newPhone,
	})
	patchReq, _ := http.NewRequest(http.MethodPatch, server.URL+"/v1/users/me", bytes.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+token)
	patchReq.Header.Set("If-Match", "\"1\"")
	patchReq.Header.Set("Content-Type", "application/json")

	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("patch request failed: %v", err)
	}
	defer patchResp.Body.Close()

	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for patch, got %d", patchResp.StatusCode)
	}

	// Verify users.profile_updated.v1 is in events.outbox_events
	var updatedCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM events.outbox_events
		WHERE aggregate_type = 'users.user_profiles'
		  AND aggregate_id = $1
		  AND aggregate_version = 2
		  AND event_type = 'users.profile_updated.v1'
	`, userID).Scan(&updatedCount)
	if err != nil {
		t.Fatalf("failed to query outbox for updated event: %v", err)
	}
	if updatedCount != 1 {
		t.Errorf("expected 1 users.profile_updated.v1 event, got %d", updatedCount)
	}
}

// TestProfile_UniqueConstraintHandling verifies distinct handling for duplicate user IDs versus duplicate phone numbers.
func TestProfile_UniqueConstraintHandling(t *testing.T) {
	server, db, usersSvc := setupProfileTestServer(t)
	defer server.Close()
	defer db.Close()

	email1 := fmt.Sprintf("uniq1_%d@example.com", time.Now().UnixNano())
	userID1, _ := registerAndLoginUser(t, server, email1)

	phone1 := uniquePhone()
	_, err := usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userID1,
		LegalGivenName:  "Primary",
		LegalFamilyName: "User",
		DateOfBirth:     "1991-01-01",
		PhoneE164:       phone1,
		Address: users.AddressInput{
			Line1:       "1 Main St",
			City:        "Boston",
			CountryCode: "US",
		},
	})
	if err != nil {
		t.Fatalf("failed to create initial profile: %v", err)
	}

	// 1. Attempting duplicate user_id must return ErrProfileAlreadyExists
	phone2 := uniquePhone()
	_, err = usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userID1, // duplicate user_id!
		LegalGivenName:  "Primary",
		LegalFamilyName: "User",
		DateOfBirth:     "1991-01-01",
		PhoneE164:       phone2,
		Address: users.AddressInput{
			Line1:       "1 Main St",
			City:        "Boston",
			CountryCode: "US",
		},
	})
	if !errors.Is(err, users.ErrProfileAlreadyExists) {
		t.Errorf("expected ErrProfileAlreadyExists on duplicate user_id, got: %v", err)
	}

	// 2. Attempting duplicate phone must return ErrDuplicatePhone
	email2 := fmt.Sprintf("uniq2_%d@example.com", time.Now().UnixNano())
	userID2, _ := registerAndLoginUser(t, server, email2)

	_, err = usersSvc.CreateProfile(context.Background(), users.CreateProfileRequest{
		UserID:          userID2,
		LegalGivenName:  "Second",
		LegalFamilyName: "User",
		DateOfBirth:     "1992-02-02",
		PhoneE164:       phone1, // duplicate phone!
		Address: users.AddressInput{
			Line1:       "2 Main St",
			City:        "Boston",
			CountryCode: "US",
		},
	})
	if !errors.Is(err, users.ErrDuplicatePhone) {
		t.Errorf("expected ErrDuplicatePhone on duplicate phone, got: %v", err)
	}
}
