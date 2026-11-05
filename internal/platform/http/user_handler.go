package platformhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
	"github.com/Davysongs/TopChoiceBank/internal/users"
	"github.com/Davysongs/TopChoiceBank/internal/users/domain"
)

// RegisterUserRoutes registers user profile endpoints on the router.
func RegisterUserRoutes(router *Router, service *users.Service, jwtSecret string) {
	router.HandleFunc("/v1/users/me", handleUserMe(service, jwtSecret))
}

// handleUserMe routes GET and PATCH requests for /v1/users/me.
func handleUserMe(service *users.Service, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := authenticateUser(w, r, jwtSecret)
		if !ok {
			return
		}

		switch r.Method {
		case http.MethodGet:
			handleGetProfile(w, r, service, userID)
		case http.MethodPatch:
			handlePatchProfile(w, r, service, userID)
		default:
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "Method not allowed on /v1/users/me", r.URL.Path)
		}
	}
}

// authenticateUser validates the Authorization Bearer JWT header and returns the authenticated user ID.
func authenticateUser(w http.ResponseWriter, r *http.Request, jwtSecret string) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if strings.TrimSpace(authHeader) == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Bearer access token is required", r.URL.Path)
		return "", false
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := security.VerifyAccessToken(jwtSecret, tokenStr, time.Now().UTC())
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Invalid or expired access token", r.URL.Path)
		return "", false
	}

	return claims.Subject, true
}

// handleGetProfile handles GET /v1/users/me, returning the caller's profile and current ETag version.
func handleGetProfile(w http.ResponseWriter, r *http.Request, service *users.Service, userID string) {
	profile, err := service.GetProfile(r.Context(), userID)
	if err != nil {
		if errors.Is(err, users.ErrProfileNotFound) {
			writeProblem(w, http.StatusNotFound, "Profile Not Found", "Profile does not exist for this user", r.URL.Path)
			return
		}
		writeProblem(w, http.StatusInternalServerError, "Internal Error", "Failed to retrieve user profile", r.URL.Path)
		return
	}

	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", profile.Version))
	writeJSON(w, http.StatusOK, profile)
}

// handlePatchProfile handles PATCH /v1/users/me, enforcing If-Match optimistic concurrency
// and rejecting attempts to modify immutable legal identity fields.
func handlePatchProfile(w http.ResponseWriter, r *http.Request, service *users.Service, userID string) {
	ifMatch := r.Header.Get("If-Match")
	if strings.TrimSpace(ifMatch) == "" {
		writeProblem(w, http.StatusBadRequest, "Precondition Required", "If-Match header is required for optimistic concurrency", r.URL.Path)
		return
	}

	cleanVersion := strings.Trim(strings.TrimSpace(ifMatch), "\"")
	version, err := strconv.ParseInt(cleanVersion, 10, 64)
	if err != nil || version < 1 {
		writeProblem(w, http.StatusBadRequest, "Invalid If-Match", "If-Match header must contain a valid positive version number", r.URL.Path)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Malformed Request", "Failed to read request body", r.URL.Path)
		return
	}

	// Verify immutable fields are not present in request payload
	var rawMap map[string]any
	if err := json.Unmarshal(bodyBytes, &rawMap); err != nil {
		writeProblem(w, http.StatusBadRequest, "Malformed JSON", "Request body must be valid JSON", r.URL.Path)
		return
	}

	immutableFields := []string{"legal_name", "legal_given_name", "legal_family_name", "date_of_birth", "user_id", "id"}
	for _, field := range immutableFields {
		if _, exists := rawMap[field]; exists {
			writeProblem(w, http.StatusForbidden, "Forbidden Field", "Legal identity fields are immutable; modifications require a new KYC case", r.URL.Path)
			return
		}
	}

	var req users.UpdateProfileRequest
	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "Invalid Request Body", err.Error(), r.URL.Path)
		return
	}

	profile, err := service.UpdateProfile(r.Context(), userID, version, req)
	if err != nil {
		switch {
		case errors.Is(err, users.ErrVersionConflict):
			writeProblem(w, http.StatusConflict, "Version Conflict", "Supplied profile version is stale or conflicted", r.URL.Path)
		case errors.Is(err, users.ErrProfileNotFound):
			writeProblem(w, http.StatusNotFound, "Profile Not Found", "Profile does not exist for this user", r.URL.Path)
		case errors.Is(err, users.ErrDuplicatePhone):
			writeProblem(w, http.StatusConflict, "Phone Conflict", "Phone number is already registered to another account", r.URL.Path)
		case errors.Is(err, domain.ErrInvalidPhoneNumber),
			errors.Is(err, domain.ErrEmptyAddressLine1),
			errors.Is(err, domain.ErrAddressLine1TooLong),
			errors.Is(err, domain.ErrAddressLine2TooLong),
			errors.Is(err, domain.ErrEmptyCity),
			errors.Is(err, domain.ErrCityTooLong),
			errors.Is(err, domain.ErrRegionTooLong),
			errors.Is(err, domain.ErrPostalCodeTooLong),
			errors.Is(err, domain.ErrInvalidCountryCode):
			writeProblem(w, http.StatusUnprocessableEntity, "Validation Error", err.Error(), r.URL.Path)
		default:
			writeProblem(w, http.StatusInternalServerError, "Internal Error", "Failed to update user profile", r.URL.Path)
		}
		return
	}

	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", profile.Version))
	writeJSON(w, http.StatusOK, profile)
}

