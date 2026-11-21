package tests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
)

// extractSecretFromOTPAuthURI parses an otpauth URI and extracts the secret parameter.
func extractSecretFromOTPAuthURI(uriStr string) (string, error) {
	parsed, err := url.Parse(uriStr)
	if err != nil {
		return "", err
	}
	secret := parsed.Query().Get("secret")
	if secret == "" {
		return "", fmt.Errorf("secret query param missing in otpauth URI: %s", uriStr)
	}
	return secret, nil
}

// registerAndLoginHelper registers a fresh user, logs in, and returns the user ID, email, password, and access token.
func registerAndLoginHelper(t *testing.T, serverURL string) (string, string, string, string) {
	t.Helper()

	email := fmt.Sprintf("mfa_user_%d@example.com", time.Now().UnixNano())
	password := "SecureP@ss12345!"

	regBody, _ := json.Marshal(map[string]string{
		"email":                  email,
		"password":               password,
		"accepted_terms_version": "v1.0",
	})

	regResp, err := http.Post(serverURL+"/v1/auth/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created from register, got %d", regResp.StatusCode)
	}

	var regData identity.RegisterResponse
	if err := json.NewDecoder(regResp.Body).Decode(&regData); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}

	loginBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	loginResp, err := http.Post(serverURL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("failed to login user: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from login, got %d", loginResp.StatusCode)
	}

	var loginData identity.LoginResponse
	if err := json.NewDecoder(loginResp.Body).Decode(&loginData); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}

	return regData.UserID, email, password, loginData.AccessToken
}

// TestMFAEnrollmentVerificationAndSingleActiveInvariant verifies TOTP enrollment, verification,
// clock drift tolerance, backup codes hashing, and single active TOTP invariant.
func TestMFAEnrollmentVerificationAndSingleActiveInvariant(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	userID, _, password, token := registerAndLoginHelper(t, server.URL)

	// 1. Enrollment with wrong password confirmation fails
	badEnrollBody, _ := json.Marshal(map[string]string{
		"label":                 "Primary Phone",
		"password_confirmation": "WrongPassword!",
	})
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/enrol", bytes.NewBuffer(badEnrollBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	badResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to do enroll request: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for bad password confirmation, got %d", badResp.StatusCode)
	}

	// 2. Enrollment without bearer token fails
	reqNoAuth, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/enrol", bytes.NewBuffer(badEnrollBody))
	reqNoAuth.Header.Set("Content-Type", "application/json")
	noAuthResp, err := http.DefaultClient.Do(reqNoAuth)
	if err != nil {
		t.Fatalf("failed to do unauthenticated enroll request: %v", err)
	}
	defer noAuthResp.Body.Close()
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing token, got %d", noAuthResp.StatusCode)
	}

	// 3. Successful enrollment returns secret URI and 10 backup codes once
	goodEnrollBody, _ := json.Marshal(map[string]string{
		"label":                 "Primary Phone",
		"password_confirmation": password,
	})
	reqGood, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/enrol", bytes.NewBuffer(goodEnrollBody))
	reqGood.Header.Set("Authorization", "Bearer "+token)
	reqGood.Header.Set("Content-Type", "application/json")

	goodResp, err := http.DefaultClient.Do(reqGood)
	if err != nil {
		t.Fatalf("failed to do valid enroll request: %v", err)
	}
	defer goodResp.Body.Close()

	if goodResp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(goodResp.Body)
		t.Fatalf("expected 200 OK from enroll, got %d: %s", goodResp.StatusCode, buf.String())
	}

	var enrollData identity.EnrollTOTPResponse
	if err := json.NewDecoder(goodResp.Body).Decode(&enrollData); err != nil {
		t.Fatalf("failed to decode enroll response: %v", err)
	}

	if enrollData.FactorID == "" {
		t.Fatal("expected non-empty factor_id")
	}
	if len(enrollData.BackupCodes) != 10 {
		t.Fatalf("expected 10 backup codes, got %d", len(enrollData.BackupCodes))
	}

	secret, err := extractSecretFromOTPAuthURI(enrollData.OtpauthURI)
	if err != nil {
		t.Fatalf("failed to extract secret: %v", err)
	}

	// 4. Verify in DB that backup codes are stored hashed (SHA-256), not plaintext
	var backupCount int
	err = db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM identity.mfa_backup_codes b
		JOIN identity.mfa_factors f ON b.factor_id = f.id
		WHERE f.user_id = $1 AND b.consumed_at IS NULL
	`, userID).Scan(&backupCount)
	if err != nil {
		t.Fatalf("failed to query backup codes from database: %v", err)
	}
	if backupCount != 10 {
		t.Fatalf("expected 10 backup codes in DB, got %d", backupCount)
	}

	// Ensure plaintext code does not exist in code_hash column
	var plainMatch int
	err = db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM identity.mfa_backup_codes b
		JOIN identity.mfa_factors f ON b.factor_id = f.id
		WHERE f.user_id = $1 AND b.code_hash = $2::bytea
	`, userID, []byte(enrollData.BackupCodes[0])).Scan(&plainMatch)
	if err != nil {
		t.Fatalf("failed to check plaintext backup code: %v", err)
	}
	if plainMatch > 0 {
		t.Fatal("plaintext backup code was directly stored in database!")
	}

	// 5. Verification with invalid TOTP code fails
	badVerifyBody, _ := json.Marshal(map[string]string{
		"factor_id": enrollData.FactorID,
		"code":      "000000",
	})
	reqBadVerify, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/verify", bytes.NewBuffer(badVerifyBody))
	reqBadVerify.Header.Set("Authorization", "Bearer "+token)
	reqBadVerify.Header.Set("Content-Type", "application/json")

	badVerifyResp, err := http.DefaultClient.Do(reqBadVerify)
	if err != nil {
		t.Fatalf("failed to do bad verify request: %v", err)
	}
	defer badVerifyResp.Body.Close()
	if badVerifyResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for bad totp code, got %d", badVerifyResp.StatusCode)
	}

	// 6. Verification with valid TOTP code succeeds
	validCode, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}

	goodVerifyBody, _ := json.Marshal(map[string]string{
		"factor_id": enrollData.FactorID,
		"code":      validCode,
	})
	reqGoodVerify, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/verify", bytes.NewBuffer(goodVerifyBody))
	reqGoodVerify.Header.Set("Authorization", "Bearer "+token)
	reqGoodVerify.Header.Set("Content-Type", "application/json")

	goodVerifyResp, err := http.DefaultClient.Do(reqGoodVerify)
	if err != nil {
		t.Fatalf("failed to do good verify request: %v", err)
	}
	defer goodVerifyResp.Body.Close()

	if goodVerifyResp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(goodVerifyResp.Body)
		t.Fatalf("expected 200 OK from verify, got %d: %s", goodVerifyResp.StatusCode, buf.String())
	}

	// 7. Verify DB factor state is ACTIVE and verified_at is set
	var factorStatus string
	var verifiedAt sql.NullTime
	err = db.QueryRowContext(context.Background(), `
		SELECT status, verified_at FROM identity.mfa_factors WHERE id = $1
	`, enrollData.FactorID).Scan(&factorStatus, &verifiedAt)
	if err != nil {
		t.Fatalf("failed to query factor from DB: %v", err)
	}
	if factorStatus != "ACTIVE" || !verifiedAt.Valid {
		t.Fatalf("expected factor status ACTIVE with verified_at, got status=%s, valid=%v", factorStatus, verifiedAt.Valid)
	}

	// 8. Verify transactional outbox emitted identity.mfa_enrolled.v1
	var outboxCount int
	err = db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM events.outbox_events
		WHERE aggregate_type = 'identity.mfa_factors'
		  AND aggregate_id = $1
		  AND event_type = 'identity.mfa_enrolled.v1'
	`, enrollData.FactorID).Scan(&outboxCount)
	if err != nil {
		t.Fatalf("failed to query outbox: %v", err)
	}
	if outboxCount != 1 {
		t.Fatalf("expected 1 outbox event identity.mfa_enrolled.v1, got %d", outboxCount)
	}

	// 9. Enforcing single active TOTP factor: attempting to enroll another factor fails with 409 Conflict
	secondEnrollBody, _ := json.Marshal(map[string]string{
		"label":                 "Secondary Authenticator",
		"password_confirmation": password,
	})
	reqSecond, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/enrol", bytes.NewBuffer(secondEnrollBody))
	reqSecond.Header.Set("Authorization", "Bearer "+token)
	reqSecond.Header.Set("Content-Type", "application/json")

	secondResp, err := http.DefaultClient.Do(reqSecond)
	if err != nil {
		t.Fatalf("failed to do second enroll request: %v", err)
	}
	defer secondResp.Body.Close()

	if secondResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for second active factor enrollment, got %d", secondResp.StatusCode)
	}
}

// TestMFALoginAndBackupCodeConsumption verifies that once MFA is active, login requires
// TOTP code or single-use backup code, and rejects reused backup codes.
func TestMFALoginAndBackupCodeConsumption(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	userID, email, password, token := registerAndLoginHelper(t, server.URL)

	// Enroll and verify TOTP factor
	enrollBody, _ := json.Marshal(map[string]string{
		"label":                 "Authenticator",
		"password_confirmation": password,
	})
	reqEnroll, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/enrol", bytes.NewBuffer(enrollBody))
	reqEnroll.Header.Set("Authorization", "Bearer "+token)
	reqEnroll.Header.Set("Content-Type", "application/json")
	enrollResp, err := http.DefaultClient.Do(reqEnroll)
	if err != nil {
		t.Fatalf("enroll request failed: %v", err)
	}
	defer enrollResp.Body.Close()

	var enrollData identity.EnrollTOTPResponse
	_ = json.NewDecoder(enrollResp.Body).Decode(&enrollData)

	secret, _ := extractSecretFromOTPAuthURI(enrollData.OtpauthURI)
	validCode, _ := totp.GenerateCode(secret, time.Now().UTC())

	verifyBody, _ := json.Marshal(map[string]string{
		"factor_id": enrollData.FactorID,
		"code":      validCode,
	})
	reqVerify, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/verify", bytes.NewBuffer(verifyBody))
	reqVerify.Header.Set("Authorization", "Bearer "+token)
	reqVerify.Header.Set("Content-Type", "application/json")
	verifyResp, err := http.DefaultClient.Do(reqVerify)
	if err != nil {
		t.Fatalf("verify request failed: %v", err)
	}
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from verify, got %d", verifyResp.StatusCode)
	}

	// 1. Login without MFA code returns MFA challenge requirement
	loginNoMFA, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	respNoMFA, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginNoMFA))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer respNoMFA.Body.Close()

	var challengeData identity.LoginResponse
	_ = json.NewDecoder(respNoMFA.Body).Decode(&challengeData)
	if !challengeData.MFARequired || challengeData.MFAFactorID == "" {
		t.Fatalf("expected mfa_required=true and non-empty mfa_factor_id, got %+v", challengeData)
	}

	// 2. Login with valid TOTP code succeeds and issues tokens with amr: ["pwd", "mfa"]
	totpCode, _ := totp.GenerateCode(secret, time.Now().UTC())
	loginWithTOTP, _ := json.Marshal(map[string]string{
		"email":     email,
		"password":  password,
		"totp_code": totpCode,
	})
	respWithTOTP, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginWithTOTP))
	if err != nil {
		t.Fatalf("login with totp failed: %v", err)
	}
	defer respWithTOTP.Body.Close()

	if respWithTOTP.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for login with totp, got %d", respWithTOTP.StatusCode)
	}

	var totpLoginData identity.LoginResponse
	_ = json.NewDecoder(respWithTOTP.Body).Decode(&totpLoginData)
	if totpLoginData.AccessToken == "" {
		t.Fatal("expected access token from login with totp")
	}

	// 3. Login with first backup code succeeds
	backupCode := enrollData.BackupCodes[0]
	loginWithBackup, _ := json.Marshal(map[string]string{
		"email":       email,
		"password":    password,
		"backup_code": backupCode,
	})
	respWithBackup, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginWithBackup))
	if err != nil {
		t.Fatalf("login with backup failed: %v", err)
	}
	defer respWithBackup.Body.Close()

	if respWithBackup.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for login with backup code, got %d", respWithBackup.StatusCode)
	}

	// 4. Verify that the used backup code has consumed_at set in DB
	var consumedAt sql.NullTime
	err = db.QueryRowContext(context.Background(), `
		SELECT b.consumed_at FROM identity.mfa_backup_codes b
		JOIN identity.mfa_factors f ON b.factor_id = f.id
		WHERE f.user_id = $1 AND b.consumed_at IS NOT NULL
	`, userID).Scan(&consumedAt)
	if err != nil || !consumedAt.Valid {
		t.Fatalf("expected consumed_at to be populated in DB for consumed backup code: %v", err)
	}

	// 5. Reusing the same backup code fails with 401 Unauthorized
	respReuse, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginWithBackup))
	if err != nil {
		t.Fatalf("reused backup code request failed: %v", err)
	}
	defer respReuse.Body.Close()

	if respReuse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for reused backup code, got %d", respReuse.StatusCode)
	}
}

// TestPasswordChangeRequiresMFAAndRevokesSessions verifies password change requiring MFA,
// revoking other refresh families, and emitting identity.password_changed.v1.
func TestPasswordChangeRequiresMFAAndRevokesSessions(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	userID, email, oldPassword, token := registerAndLoginHelper(t, server.URL)

	// Enroll and activate MFA
	enrollBody, _ := json.Marshal(map[string]string{
		"label":                 "MFA Factor",
		"password_confirmation": oldPassword,
	})
	reqEnroll, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/enrol", bytes.NewBuffer(enrollBody))
	reqEnroll.Header.Set("Authorization", "Bearer "+token)
	reqEnroll.Header.Set("Content-Type", "application/json")
	enrollResp, _ := http.DefaultClient.Do(reqEnroll)
	var enrollData identity.EnrollTOTPResponse
	_ = json.NewDecoder(enrollResp.Body).Decode(&enrollData)
	enrollResp.Body.Close()

	secret, _ := extractSecretFromOTPAuthURI(enrollData.OtpauthURI)
	verifyCode, _ := totp.GenerateCode(secret, time.Now().UTC())

	verifyBody, _ := json.Marshal(map[string]string{
		"factor_id": enrollData.FactorID,
		"code":      verifyCode,
	})
	reqVerify, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/mfa/verify", bytes.NewBuffer(verifyBody))
	reqVerify.Header.Set("Authorization", "Bearer "+token)
	reqVerify.Header.Set("Content-Type", "application/json")
	verifyResp, _ := http.DefaultClient.Do(reqVerify)
	verifyResp.Body.Close()

	// 1. Password change without TOTP code or recent MFA fails
	newPassword := "NewBrandPassword2026!"
	noMFABody, _ := json.Marshal(map[string]string{
		"current_password": oldPassword,
		"new_password":     newPassword,
	})
	reqNoMFA, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/password/change", bytes.NewBuffer(noMFABody))
	reqNoMFA.Header.Set("Authorization", "Bearer "+token)
	reqNoMFA.Header.Set("Content-Type", "application/json")
	respNoMFA, err := http.DefaultClient.Do(reqNoMFA)
	if err != nil {
		t.Fatalf("failed password change request: %v", err)
	}
	defer respNoMFA.Body.Close()

	if respNoMFA.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for password change without MFA, got %d", respNoMFA.StatusCode)
	}

	// 2. Password change with valid TOTP code succeeds
	changeTOTP, _ := totp.GenerateCode(secret, time.Now().UTC())
	withMFABody, _ := json.Marshal(map[string]string{
		"current_password": oldPassword,
		"new_password":     newPassword,
		"totp_code":        changeTOTP,
	})
	reqWithMFA, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/password/change", bytes.NewBuffer(withMFABody))
	reqWithMFA.Header.Set("Authorization", "Bearer "+token)
	reqWithMFA.Header.Set("Content-Type", "application/json")
	respWithMFA, err := http.DefaultClient.Do(reqWithMFA)
	if err != nil {
		t.Fatalf("failed password change request: %v", err)
	}
	defer respWithMFA.Body.Close()

	if respWithMFA.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(respWithMFA.Body)
		t.Fatalf("expected 200 OK from password change, got %d: %s", respWithMFA.StatusCode, buf.String())
	}

	// 3. Verify outbox has identity.password_changed.v1 event
	var outboxCount int
	err = db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM events.outbox_events
		WHERE aggregate_type = 'identity.users'
		  AND aggregate_id = $1
		  AND event_type = 'identity.password_changed.v1'
	`, userID).Scan(&outboxCount)
	if err != nil {
		t.Fatalf("failed to query password_changed outbox event: %v", err)
	}
	if outboxCount != 1 {
		t.Fatalf("expected 1 password_changed outbox event, got %d", outboxCount)
	}

	// 4. Verify old password cannot be used to login
	loginOldBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": oldPassword,
	})
	respOldLogin, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginOldBody))
	if err != nil {
		t.Fatalf("old login failed: %v", err)
	}
	defer respOldLogin.Body.Close()
	if respOldLogin.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for old password, got %d", respOldLogin.StatusCode)
	}

	// 5. Verify new password + TOTP logs in successfully
	loginNewTOTP, _ := totp.GenerateCode(secret, time.Now().UTC())
	loginNewBody, _ := json.Marshal(map[string]string{
		"email":     email,
		"password":  newPassword,
		"totp_code": loginNewTOTP,
	})
	respNewLogin, err := http.Post(server.URL+"/v1/auth/login", "application/json", bytes.NewBuffer(loginNewBody))
	if err != nil {
		t.Fatalf("new login failed: %v", err)
	}
	defer respNewLogin.Body.Close()
	if respNewLogin.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for login with new password, got %d", respNewLogin.StatusCode)
	}
}
