package platformhttp

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/identity/domain"
	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
)

type claimsContextKeyType string

// ClaimsContextKey is the context key under which authenticated JWT claims are stored.
const ClaimsContextKey claimsContextKeyType = "jwt_claims"

// ContextWithClaims injects the authenticated JWT claims into the request context.
func ContextWithClaims(ctx context.Context, claims *security.JWTClaims) context.Context {
	return context.WithValue(ctx, ClaimsContextKey, claims)
}

// ClaimsFromContext retrieves the authenticated JWT claims from the request context, if present.
func ClaimsFromContext(ctx context.Context) (*security.JWTClaims, bool) {
	val := ctx.Value(ClaimsContextKey)
	if val == nil {
		return nil, false
	}
	claims, ok := val.(*security.JWTClaims)
	return claims, ok
}

// RequireAuth returns a route middleware that validates the Bearer token and injects claims into context.
func RequireAuth(jwtSecret string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if strings.TrimSpace(authHeader) == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Bearer access token is required", r.URL.Path)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := security.VerifyAccessToken(jwtSecret, tokenStr, time.Now().UTC())
			if err != nil {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Invalid or expired access token", r.URL.Path)
				return
			}

			ctx := ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRoles returns a route middleware that enforces that caller possesses at least one allowed role.
func RequireRoles(allowedRoles ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication required", r.URL.Path)
				return
			}

			if !domain.HasAnyRole(claims.Roles, allowedRoles...) {
				writeProblem(w, http.StatusForbidden, "Role Denied", "User role does not grant access to this endpoint", r.URL.Path)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireScopes returns a route middleware that enforces that caller possesses all required scopes.
func RequireScopes(requiredScopes ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication required", r.URL.Path)
				return
			}

			if !domain.HasAllScopes(claims.Scopes, requiredScopes...) {
				writeProblem(w, http.StatusForbidden, "Scope Denied", "Insufficient scope for requested resource", r.URL.Path)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRecentMFA returns a route middleware gating actions behind recent MFA verification.
func RequireRecentMFA(maxAge time.Duration) Middleware {
	if maxAge <= 0 {
		maxAge = 15 * time.Minute
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication required", r.URL.Path)
				return
			}

			hasMFA := false
			for _, m := range claims.AMR {
				if m == "mfa" {
					hasMFA = true
					break
				}
			}

			if !hasMFA {
				writeProblem(w, http.StatusForbidden, "Recent MFA Required", "Multi-factor authentication required for this action", r.URL.Path)
				return
			}

			if claims.AuthTime <= 0 || time.Since(time.Unix(claims.AuthTime, 0)) > maxAge {
				writeProblem(w, http.StatusForbidden, "Recent MFA Required", "MFA verification has expired; re-authentication required", r.URL.Path)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CheckResourceOwnership validates whether the authenticated subject owns the resource or has administrative override.
func CheckResourceOwnership(claims *security.JWTClaims, resourceOwnerID string) bool {
	if claims == nil {
		return false
	}
	if claims.Subject == resourceOwnerID {
		return true
	}
	return domain.HasRole(claims.Roles, domain.RoleAdmin)
}
