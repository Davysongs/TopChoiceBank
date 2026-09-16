package platformhttp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
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
			if errors.Is(err, identity.ErrInvalidCredentials) {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Invalid email or password", r.URL.Path)
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
			writeProblem(w, http.StatusInternalServerError, "Internal Server Error", "An error occurred refreshing token", r.URL.Path)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
