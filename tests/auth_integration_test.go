package tests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	platformhttp "github.com/Davysongs/TopChoiceBank/internal/platform/http"
	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
)

// setupTestServer creates a migrated database and an HTTP server for authentication tests.
func setupTestServer(t *testing.T) (*httptest.Server, *sql.DB) {
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
		t.Skipf("skipping integration test: database connection unpingable: %v", err)
	}

	// Apply migrations
	migCtx, migCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer migCancel()

	if err := platformdb.ApplyIdentityBootstrapMigrations(migCtx, db); err != nil {
		t.Fatalf("failed to apply migrations: %v", err)
	}

	logger := logging.New("error")
	router := platformhttp.NewRouter()
	router.Use(platformhttp.RequestIDMiddleware())
	router.Use(platformhttp.RequestLoggerMiddleware(logger))

	repo := identity.NewPostgresRepository(db)
	svc := identity.NewService(repo, "integration-test-jwt-secret-key-32bytes")
	platformhttp.RegisterAuthRoutes(router, svc)

	server := httptest.NewServer(router.Handler())
	return server, db
}

// TestRegistrationAndOutboxEmission verifies registration persistence and event emission.
func TestRegistrationAndOutboxEmission(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	testEmail := fmt.Sprintf("test_reg_%d@example.com", time.Now().UnixNano())
	payload := map[string]string{
		"email":                  testEmail,
		"password":               "P@ssword12345!",
		"accepted_terms_version": "v1.0",
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(server.URL+"/v1/auth/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("unexpected error making register request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		t.Fatalf("expected status 201 Created, got %d. Body: %s", resp.StatusCode, buf.String())
	}

	var regResp identity.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}

	if regResp.UserID == "" {
		t.Fatal("expected non-empty user_id in response")
	}
	if regResp.Status != "PENDING" {
		t.Fatalf("expected status PENDING, got %s", regResp.Status)
	}

	// Verify identity.user_registered.v1 event emission to events.outbox_events
	var eventType string
	var aggregateID string
	var payloadJSON string
	err = db.QueryRow(`
		SELECT event_type, aggregate_id, payload::text
		FROM events.outbox_events
		WHERE aggregate_type = 'identity.users' AND aggregate_id = $1
		ORDER BY sequence_id DESC LIMIT 1
	`, regResp.UserID).Scan(&eventType, &aggregateID, &payloadJSON)

	if err != nil {
		t.Fatalf("expected outbox event in events.outbox_events table, got error: %v", err)
	}
	if eventType != "identity.user_registered.v1" {
		t.Fatalf("expected event_type identity.user_registered.v1, got %s", eventType)
	}
	if aggregateID != regResp.UserID {
		t.Fatalf("expected aggregate_id %s, got %s", regResp.UserID, aggregateID)
	}

	var payloadMap map[string]any
	if err := json.Unmarshal([]byte(payloadJSON), &payloadMap); err != nil {
		t.Fatalf("failed to parse outbox payload: %v", err)
	}
	if payloadMap["accepted_terms_version"] != "v1.0" {
		t.Fatalf("expected accepted_terms_version v1.0, got %v", payloadMap["accepted_terms_version"])
	}
	if _, ok := payloadMap["accepted_terms_at"]; !ok {
		t.Fatalf("expected accepted_terms_at in outbox payload")
	}

	// Duplicate registration check -> 409 Conflict
	respDup, err := http.Post(server.URL+"/v1/auth/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("unexpected error making duplicate register request: %v", err)
	}
	defer respDup.Body.Close()

	if respDup.StatusCode != http.StatusConflict {
		t.Fatalf("expected status 409 Conflict on duplicate registration, got %d", respDup.StatusCode)
	}
}

// TestAccountLockoutPolicyAfterFiveFailedAttempts verifies the failed-login lockout policy.
func TestAccountLockoutPolicyAfterFiveFailedAttempts(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	testEmail := fmt.Sprintf("test_lockout_%d@example.com", time.Now().UnixNano())
	password := "CorrectP@ssword123!"

	// Register user
	regPayload := map[string]string{
		"email":                  testEmail,
		"password":               password,
		"accepted_terms_version": "v1.0",
	}
	regBody, _ := json.Marshal(regPayload)
	regResp, err := http.Post(server.URL+"/v1/auth/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("failed to register user for lockout test: %v", err)
	}
	if regResp.StatusCode != http.StatusCreated {
		regResp.Body.Close()
		t.Fatalf("failed to register user for lockout test, got status %d", regResp.StatusCode)
	}
	regResp.Body.Close()

	// Perform 5 failed login attempts
	wrongPayload := map[string]string{
		"email":              testEmail,
		"password":           "WrongPassword123!",
		"device_fingerprint": "dev_fp_123",
	}
	wrongBody, _ := json.Marshal(wrongPayload)

	for i := 1; i <= 5; i++ {
		resp, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(wrongBody))
		if err != nil {
			t.Fatalf("attempt %d failed with HTTP error: %v", i, err)
		}
		resp.Body.Close()
		if i < 5 && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected status 401 on failed attempt %d, got %d", i, resp.StatusCode)
		}
		if i == 5 && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 5th failed attempt to lock account and return 403 Forbidden, got %d", resp.StatusCode)
		}
	}

	// Verify account locked status and locked_until in database
	var status string
	var lockedUntil sql.NullTime
	err = db.QueryRow("SELECT status, locked_until FROM identity.users WHERE email = $1", testEmail).Scan(&status, &lockedUntil)
	if err != nil {
		t.Fatalf("failed to query user status from db: %v", err)
	}

	if status != "LOCKED" {
		t.Fatalf("expected user status to be LOCKED in database, got %s", status)
	}
	if !lockedUntil.Valid || lockedUntil.Time.Before(time.Now().UTC()) {
		t.Fatalf("expected valid future locked_until timestamp, got %v", lockedUntil)
	}

	// 6th attempt even with CORRECT password should be rejected with 403 Forbidden
	correctPayload := map[string]string{
		"email":              testEmail,
		"password":           password,
		"device_fingerprint": "dev_fp_123",
	}
	correctBody, _ := json.Marshal(correctPayload)
	respLocked, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(correctBody))
	if err != nil {
		t.Fatalf("unexpected error making request to locked account: %v", err)
	}
	defer respLocked.Body.Close()

	if respLocked.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for locked account login, got %d", respLocked.StatusCode)
	}
}

// TestRefreshTokenRotationAndReuseRevocation verifies rotation and refresh-token reuse handling.
func TestRefreshTokenRotationAndReuseRevocation(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	testEmail := fmt.Sprintf("test_refresh_%d@example.com", time.Now().UnixNano())
	password := "ValidP@ssword123!"

	// Register user
	regPayload := map[string]string{
		"email":                  testEmail,
		"password":               password,
		"accepted_terms_version": "v1.0",
	}
	regBody, _ := json.Marshal(regPayload)
	regResp, err := http.Post(server.URL+"/v1/auth/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("failed to register user for refresh test: %v", err)
	}
	if regResp.StatusCode != http.StatusCreated {
		regResp.Body.Close()
		t.Fatalf("failed to register user for refresh test, got status %d", regResp.StatusCode)
	}
	regResp.Body.Close()

	// Perform successful login
	loginPayload := map[string]string{
		"email":              testEmail,
		"password":           password,
		"device_fingerprint": "dev_fp_456",
	}
	loginBody, _ := json.Marshal(loginPayload)
	loginResp, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(loginResp.Body)
		loginResp.Body.Close()
		t.Fatalf("expected login status 200 OK, got %d. Body: %s", loginResp.StatusCode, buf.String())
	}

	var loginData identity.LoginResponse
	_ = json.NewDecoder(loginResp.Body).Decode(&loginData)
	loginResp.Body.Close()

	initialRefreshToken := loginData.RefreshToken
	if initialRefreshToken == "" {
		t.Fatal("expected non-empty refresh_token from login")
	}

	// Verify JWT access token claims
	claims, err := security.VerifyAccessToken("integration-test-jwt-secret-key-32bytes", loginData.AccessToken, time.Now().UTC())
	if err != nil {
		t.Fatalf("failed to verify access token JWT: %v", err)
	}
	if claims.Issuer != "topchoicebank" {
		t.Fatalf("expected issuer topchoicebank, got %s", claims.Issuer)
	}

	// Perform legitimate refresh
	refreshPayload := map[string]string{
		"refresh_token":      initialRefreshToken,
		"device_fingerprint": "dev_fp_456",
	}
	refreshBody, _ := json.Marshal(refreshPayload)
	refreshResp, err := http.Post(server.URL+"/v1/auth/refresh", "application/json", bytes.NewBuffer(refreshBody))
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	if refreshResp.StatusCode != http.StatusOK {
		refreshResp.Body.Close()
		t.Fatalf("expected status 200 OK for refresh, got %d", refreshResp.StatusCode)
	}

	var refreshData identity.LoginResponse
	_ = json.NewDecoder(refreshResp.Body).Decode(&refreshData)
	refreshResp.Body.Close()

	rotatedRefreshToken := refreshData.RefreshToken
	if rotatedRefreshToken == "" || rotatedRefreshToken == initialRefreshToken {
		t.Fatal("expected new rotated refresh token")
	}

	// REUSE ATTACK: Attempt to reuse initialRefreshToken again
	reusePayload := map[string]string{
		"refresh_token":      initialRefreshToken,
		"device_fingerprint": "dev_fp_456",
	}
	reuseBody, _ := json.Marshal(reusePayload)
	reuseResp, err := http.Post(server.URL+"/v1/auth/refresh", "application/json", bytes.NewBuffer(reuseBody))
	if err != nil {
		t.Fatalf("unexpected error making refresh reuse request: %v", err)
	}
	defer reuseResp.Body.Close()

	if reuseResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized for refresh token reuse, got %d", reuseResp.StatusCode)
	}

	// Verify the ENTIRE refresh family is now revoked in PostgreSQL
	var familyRevokedAt sql.NullTime
	var familyRevokedReason sql.NullString
	err = db.QueryRow(`
		SELECT f.revoked_at, f.revoked_reason
		FROM identity.refresh_families f
		JOIN identity.sessions s ON s.refresh_family_id = f.id
		WHERE s.id = $1
	`, refreshData.SessionID).Scan(&familyRevokedAt, &familyRevokedReason)

	if err != nil {
		t.Fatalf("failed to query refresh family status from database: %v", err)
	}

	if !familyRevokedAt.Valid {
		t.Fatal("expected refresh family to be marked revoked_at in database after reuse attack")
	}
	if !familyRevokedReason.Valid || familyRevokedReason.String != "reuse_detected" {
		t.Fatalf("expected revoked_reason reuse_detected, got %v", familyRevokedReason)
	}

	// Subsequent attempt using rotatedRefreshToken should ALSO be rejected because family is revoked
	subsequentPayload := map[string]string{
		"refresh_token":      rotatedRefreshToken,
		"device_fingerprint": "dev_fp_456",
	}
	subsequentBody, _ := json.Marshal(subsequentPayload)
	subsequentResp, err := http.Post(server.URL+"/v1/auth/refresh", "application/json", bytes.NewBuffer(subsequentBody))
	if err != nil {
		t.Fatalf("unexpected error making subsequent refresh request: %v", err)
	}
	defer subsequentResp.Body.Close()

	if subsequentResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized for token in revoked family, got %d", subsequentResp.StatusCode)
	}
}

func TestExpiredLockoutAutoUnlock(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	testEmail := fmt.Sprintf("test_expired_lock_%d@example.com", time.Now().UnixNano())
	password := "ValidP@ssword123!"

	regPayload := map[string]string{
		"email":                  testEmail,
		"password":               password,
		"accepted_terms_version": "v1.0",
	}
	regBody, _ := json.Marshal(regPayload)
	regResp, err := http.Post(server.URL+"/v1/auth/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", regResp.StatusCode)
	}
	regResp.Body.Close()

	// Manually set status to LOCKED with an EXPIRED locked_until timestamp (10 minutes in the past)
	pastTime := time.Now().UTC().Add(-10 * time.Minute)
	_, err = db.Exec(`
		UPDATE identity.users
		SET status = 'LOCKED', locked_until = $1
		WHERE email = $2
	`, pastTime, testEmail)
	if err != nil {
		t.Fatalf("failed to manually lock user in db: %v", err)
	}

	// Login with correct password after lock expiration
	loginPayload := map[string]string{
		"email":              testEmail,
		"password":           password,
		"device_fingerprint": "dev_fp_789",
	}
	loginBody, _ := json.Marshal(loginPayload)
	loginResp, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 OK for expired lockout login, got %d", loginResp.StatusCode)
	}

	// Verify database status is now ACTIVE and locked_until is NULL
	var status string
	var lockedUntil sql.NullTime
	err = db.QueryRow("SELECT status, locked_until FROM identity.users WHERE email = $1", testEmail).Scan(&status, &lockedUntil)
	if err != nil {
		t.Fatalf("failed to query user status from db: %v", err)
	}

	if status != "ACTIVE" {
		t.Fatalf("expected status ACTIVE in db, got %s", status)
	}
	if lockedUntil.Valid {
		t.Fatalf("expected locked_until to be NULL in db, got %v", lockedUntil)
	}
}

func TestDeviceBindingAndDisabledUserRefreshRejection(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	testEmail := fmt.Sprintf("test_device_%d@example.com", time.Now().UnixNano())
	password := "ValidP@ssword123!"

	regPayload := map[string]string{
		"email":                  testEmail,
		"password":               password,
		"accepted_terms_version": "v1.0",
	}
	regBody, _ := json.Marshal(regPayload)
	regResp, err := http.Post(server.URL+"/v1/auth/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}
	if regResp.StatusCode != http.StatusCreated {
		regResp.Body.Close()
		t.Fatalf("expected 201 Created, got %d", regResp.StatusCode)
	}
	regResp.Body.Close()

	// Login with device fingerprint
	loginPayload := map[string]string{
		"email":              testEmail,
		"password":           password,
		"device_fingerprint": "fp_test_device_123",
	}
	loginBody, _ := json.Marshal(loginPayload)
	loginResp, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("failed to login: %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		loginResp.Body.Close()
		t.Fatalf("expected 200 OK for login, got %d", loginResp.StatusCode)
	}
	var loginData identity.LoginResponse
	_ = json.NewDecoder(loginResp.Body).Decode(&loginData)
	loginResp.Body.Close()

	// Verify device record was created in identity.devices and bound to session
	var deviceID sql.NullString
	err = db.QueryRow("SELECT device_id::text FROM identity.sessions WHERE id = $1", loginData.SessionID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("failed to query session device_id: %v", err)
	}
	if !deviceID.Valid || deviceID.String == "" {
		t.Fatal("expected non-null device_id on session created with device fingerprint")
	}

	// Disable user in database
	_, err = db.Exec("UPDATE identity.users SET status = 'DISABLED' WHERE email = $1", testEmail)
	if err != nil {
		t.Fatalf("failed to disable user in db: %v", err)
	}

	// Attempt refresh while user is DISABLED -> should be rejected with 403 Forbidden
	refreshPayload := map[string]string{
		"refresh_token":      loginData.RefreshToken,
		"device_fingerprint": "fp_test_device_123",
	}
	refreshBody, _ := json.Marshal(refreshPayload)
	refreshResp, err := http.Post(server.URL+"/v1/auth/refresh", "application/json", bytes.NewBuffer(refreshBody))
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for disabled user refresh, got %d", refreshResp.StatusCode)
	}
}
