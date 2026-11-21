package platformhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
	"github.com/Davysongs/TopChoiceBank/internal/identity/domain"
	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
)

type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
}

// writeJSON writes data as a JSON response with the supplied status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// writeProblem writes an RFC 9457-style problem response.
func writeProblem(w http.ResponseWriter, status int, title string, detail string, instance string) {
	prob := ProblemDetails{
		Type:     "about:blank",
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: instance,
	}
	writeJSON(w, status, prob)
}

// RegisterAuthRoutes registers the identity authentication endpoints on router.
func RegisterAuthRoutes(router *Router, service *identity.Service) {
	router.HandleFunc("/v1/auth/register", handleRegister(service))
	router.HandleFunc("/v1/auth/login", handleLogin(service))
	router.HandleFunc("/v1/auth/refresh", handleRefresh(service))
	router.HandleFunc("/v1/auth/mfa/enrol", handleMFAEnroll(service))
	router.HandleFunc("/v1/auth/mfa/verify", handleMFAVerify(service))
	router.HandleFunc("/v1/auth/password/change", handlePasswordChange(service))
}

const maxAuthRequestBodyBytes = 65536

// handleRegister handles customer registration requests.
func handleRegister(service *identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST is required", r.URL.Path)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
		var req identity.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed JSON", "Request body must be valid JSON", r.URL.Path)
			return
		}

		resp, err := service.Register(r.Context(), req)
		if err != nil {
			if errors.Is(err, identity.ErrDuplicateEmail) {
				writeProblem(w, http.StatusConflict, "Email Conflict", "Email address is already registered", r.URL.Path)
				return
			}
			if errors.Is(err, identity.ErrInvalidEmail) || errors.Is(err, identity.ErrWeakPassword) || errors.Is(err, identity.ErrMissingTerms) {
				writeProblem(w, http.StatusUnprocessableEntity, "Validation Error", err.Error(), r.URL.Path)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal Server Error", "An error occurred processing registration", r.URL.Path)
			return
		}

		writeJSON(w, http.StatusCreated, resp)
	}
}

// handleLogin handles credential-based login requests.
func handleLogin(service *identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST is required", r.URL.Path)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
		var req identity.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed JSON", "Request body must be valid JSON", r.URL.Path)
			return
		}

		req.RequestIP = r.RemoteAddr
		req.UserAgent = r.UserAgent()
		req.RequestID = r.Header.Get("X-Request-ID")

		resp, err := service.Login(r.Context(), req)
		if err != nil {
			if errors.Is(err, identity.ErrInvalidCredentials) || errors.Is(err, domain.ErrInvalidTOTPCode) || errors.Is(err, domain.ErrInvalidBackupCode) {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Invalid email, password, or verification code", r.URL.Path)
				return
			}
			if errors.Is(err, identity.ErrAccountLocked) || errors.Is(err, identity.ErrAccountDisabled) {
				writeProblem(w, http.StatusForbidden, "Access Forbidden", err.Error(), r.URL.Path)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal Server Error", "An error occurred processing login", r.URL.Path)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// handleRefresh handles refresh-token rotation requests.
func handleRefresh(service *identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST is required", r.URL.Path)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
		var req identity.RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed JSON", "Request body must be valid JSON", r.URL.Path)
			return
		}

		req.RequestIP = r.RemoteAddr
		req.UserAgent = r.UserAgent()
		req.RequestID = r.Header.Get("X-Request-ID")

		resp, err := service.RefreshSession(r.Context(), req)
		if err != nil {
			if errors.Is(err, identity.ErrTokenRevoked) || errors.Is(err, identity.ErrTokenExpired) || errors.Is(err, identity.ErrInvalidCredentials) {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", err.Error(), r.URL.Path)
				return
			}
			if errors.Is(err, identity.ErrAccountLocked) || errors.Is(err, identity.ErrAccountDisabled) {
				writeProblem(w, http.StatusForbidden, "Access Forbidden", err.Error(), r.URL.Path)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal Server Error", "An error occurred refreshing token", r.URL.Path)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// authenticateBearer validates the Authorization: Bearer <token> header and returns verified JWT claims.
func authenticateBearer(w http.ResponseWriter, r *http.Request, jwtSecret string) (*security.JWTClaims, bool) {
	tokenStr, ok := ParseBearerToken(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Bearer access token is required", r.URL.Path)
		return nil, false
	}

	claims, err := security.VerifyAccessToken(jwtSecret, tokenStr, time.Now().UTC())
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Invalid or expired access token", r.URL.Path)
		return nil, false
	}

	return claims, true
}

// handleMFAEnroll initiates TOTP MFA factor enrollment and returns the OTP auth URI and backup codes.
func handleMFAEnroll(service *identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST is required", r.URL.Path)
			return
		}

		claims, ok := authenticateBearer(w, r, service.JWTSecret())
		if !ok {
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
		var req struct {
			Label                string `json:"label"`
			PasswordConfirmation string `json:"password_confirmation"`
			Password             string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed JSON", "Request body must be valid JSON", r.URL.Path)
			return
		}

		password := req.PasswordConfirmation
		if password == "" {
			password = req.Password
		}
		if password == "" {
			writeProblem(w, http.StatusBadRequest, "Validation Error", "password_confirmation is required", r.URL.Path)
			return
		}

		label := req.Label
		if label == "" {
			label = "Personal Authenticator"
		}

		resp, err := service.EnrollTOTP(r.Context(), identity.EnrollTOTPRequest{
			UserID:    claims.Subject,
			Password:  password,
			Label:     label,
			RequestIP: r.RemoteAddr,
			RequestID: r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			if errors.Is(err, identity.ErrInvalidCredentials) {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Password confirmation failed", r.URL.Path)
				return
			}
			if errors.Is(err, domain.ErrFactorAlreadyActive) {
				writeProblem(w, http.StatusConflict, "Active Factor Exists", "An active MFA factor already exists for this account", r.URL.Path)
				return
			}
			if errors.Is(err, domain.ErrInvalidFactorLabel) {
				writeProblem(w, http.StatusUnprocessableEntity, "Validation Error", err.Error(), r.URL.Path)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal Server Error", "An error occurred enrolling MFA factor", r.URL.Path)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// handleMFAVerify verifies a pending TOTP factor code and activates the MFA factor.
func handleMFAVerify(service *identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST is required", r.URL.Path)
			return
		}

		claims, ok := authenticateBearer(w, r, service.JWTSecret())
		if !ok {
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
		var req struct {
			FactorID string `json:"factor_id"`
			Code     string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed JSON", "Request body must be valid JSON", r.URL.Path)
			return
		}

		if len(req.Code) != 6 {
			writeProblem(w, http.StatusBadRequest, "Validation Error", "A 6-digit TOTP code is required", r.URL.Path)
			return
		}

		resp, err := service.VerifyTOTP(r.Context(), identity.VerifyTOTPRequest{
			UserID:    claims.Subject,
			FactorID:  req.FactorID,
			TOTPCode:  req.Code,
			RequestIP: r.RemoteAddr,
			RequestID: r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			if errors.Is(err, domain.ErrInvalidTOTPCode) {
				writeProblem(w, http.StatusUnauthorized, "Invalid Code", "Invalid or expired TOTP verification code", r.URL.Path)
				return
			}
			if errors.Is(err, domain.ErrFactorAlreadyActive) || errors.Is(err, domain.ErrFactorNotPending) {
				writeProblem(w, http.StatusConflict, "Factor State Conflict", err.Error(), r.URL.Path)
				return
			}
			if strings.Contains(err.Error(), "no pending mfa factor found") {
				writeProblem(w, http.StatusNotFound, "Factor Not Found", "No pending MFA factor found for verification", r.URL.Path)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal Server Error", "An error occurred verifying MFA factor", r.URL.Path)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// handlePasswordChange handles password rotation, enforcing recent MFA or TOTP step-up verification.
func handlePasswordChange(service *identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST is required", r.URL.Path)
			return
		}

		claims, ok := authenticateBearer(w, r, service.JWTSecret())
		if !ok {
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
		var req struct {
			CurrentPassword string `json:"current_password"`
			OldPassword     string `json:"old_password"`
			NewPassword     string `json:"new_password"`
			TOTPCode        string `json:"totp_code"`
			BackupCode      string `json:"backup_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed JSON", "Request body must be valid JSON", r.URL.Path)
			return
		}

		currentPassword := req.CurrentPassword
		if currentPassword == "" {
			currentPassword = req.OldPassword
		}
		if currentPassword == "" || req.NewPassword == "" {
			writeProblem(w, http.StatusBadRequest, "Validation Error", "current_password and new_password are required", r.URL.Path)
			return
		}

		recentMFA := false
		for _, method := range claims.AMR {
			if method == "mfa" {
				if claims.AuthTime > 0 && time.Since(time.Unix(claims.AuthTime, 0)) < 10*time.Minute {
					recentMFA = true
				}
				break
			}
		}

		resp, err := service.ChangePassword(r.Context(), identity.ChangePasswordRequest{
			UserID:          claims.Subject,
			CurrentPassword: currentPassword,
			OldPassword:     currentPassword,
			NewPassword:     req.NewPassword,
			TOTPCode:        req.TOTPCode,
			BackupCode:      req.BackupCode,
			RecentMFA:       recentMFA,
			RequestIP:       r.RemoteAddr,
			RequestID:       r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			if errors.Is(err, identity.ErrInvalidCredentials) {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Invalid current password", r.URL.Path)
				return
			}
			if errors.Is(err, domain.ErrInvalidTOTPCode) {
				writeProblem(w, http.StatusUnauthorized, "Invalid Code", "Invalid TOTP verification code", r.URL.Path)
				return
			}
			if errors.Is(err, domain.ErrInvalidBackupCode) {
				writeProblem(w, http.StatusUnauthorized, "Invalid Backup Code", "Invalid or already consumed backup code", r.URL.Path)
				return
			}
			if strings.Contains(err.Error(), "recent mfa") {
				writeProblem(w, http.StatusUnauthorized, "MFA Required", "Recent MFA verification or TOTP code required", r.URL.Path)
				return
			}
			if errors.Is(err, identity.ErrWeakPassword) {
				writeProblem(w, http.StatusUnprocessableEntity, "Weak Password", "New password must be at least 8 characters long", r.URL.Path)
				return
			}
			if strings.Contains(err.Error(), "must be different") {
				writeProblem(w, http.StatusUnprocessableEntity, "Password Reuse", "New password must be different from current password", r.URL.Path)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal Server Error", "An error occurred changing password", r.URL.Path)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
