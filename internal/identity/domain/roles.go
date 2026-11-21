package domain

import (
	"sort"
)

// Supported role constants representing the four system roles.
const (
	RoleCustomer    = "customer"
	RoleAdmin       = "admin"
	RoleRiskAnalyst = "risk_analyst"
	RoleReadonly    = "readonly"
)

// Endpoint scope constants.
const (
	ScopeProfileRead       = "profile:read"
	ScopeProfileWrite      = "profile:write"
	ScopeAccountsRead      = "accounts:read"
	ScopeAccountsWrite     = "accounts:write"
	ScopeAccountsAdmin     = "accounts:admin"
	ScopeTransfersRead     = "transfers:read"
	ScopeTransfersWrite    = "transfers:write"
	ScopeTransfersReverse  = "transfers:reverse"
	ScopeCardsRead         = "cards:read"
	ScopeCardsWrite        = "cards:write"
	ScopeSavingsRead       = "savings:read"
	ScopeSavingsWrite      = "savings:write"
	ScopeSchedulesRead     = "schedules:read"
	ScopeSchedulesWrite    = "schedules:write"
	ScopeStatementsRead    = "statements:read"
	ScopeNotificationsRead = "notifications:read"
	ScopeMFAWrite          = "mfa:write"
	ScopeSessionWrite      = "session:write"
	ScopeCredentialWrite   = "credential:write"
	ScopeOAuthAuthorise    = "oauth:authorise"
	ScopeKYCRead           = "kyc:read"
	ScopeKYCWrite          = "kyc:write"
	ScopeKYCReview         = "kyc:review"
	ScopeKYCDecide         = "kyc:decide"
	ScopeRiskReview        = "risk:review"
	ScopeRiskDecide        = "risk:decide"
	ScopeFeesAdmin         = "fees:admin"
	ScopeJobsRead          = "jobs:read"
	ScopeAuditRead         = "audit:read"
)

// AllValidRoles contains the exhaustive set of allowed system roles.
var AllValidRoles = []string{
	RoleCustomer,
	RoleAdmin,
	RoleRiskAnalyst,
	RoleReadonly,
}

// IsValidRole checks whether the supplied role name matches one of the four defined roles.
func IsValidRole(role string) bool {
	switch role {
	case RoleCustomer, RoleAdmin, RoleRiskAnalyst, RoleReadonly:
		return true
	default:
		return false
	}
}

// DefaultScopesForRoles resolves the default bundle of permissions for a set of assigned roles.
func DefaultScopesForRoles(roles []string) []string {
	scopeSet := make(map[string]struct{})

	for _, role := range roles {
		switch role {
		case RoleCustomer:
			for _, s := range []string{
				ScopeProfileRead, ScopeProfileWrite,
				ScopeAccountsRead, ScopeAccountsWrite,
				ScopeTransfersRead, ScopeTransfersWrite,
				ScopeCardsRead, ScopeCardsWrite,
				ScopeSavingsRead, ScopeSavingsWrite,
				ScopeSchedulesRead, ScopeSchedulesWrite,
				ScopeStatementsRead, ScopeNotificationsRead,
				ScopeMFAWrite, ScopeSessionWrite, ScopeCredentialWrite, ScopeOAuthAuthorise,
				ScopeAuditRead,
			} {
				scopeSet[s] = struct{}{}
			}
		case RoleAdmin:
			for _, s := range []string{
				ScopeProfileRead, ScopeProfileWrite,
				ScopeAccountsRead, ScopeAccountsWrite, ScopeAccountsAdmin,
				ScopeTransfersRead, ScopeTransfersWrite, ScopeTransfersReverse,
				ScopeCardsRead, ScopeCardsWrite,
				ScopeSavingsRead, ScopeSavingsWrite,
				ScopeSchedulesRead, ScopeSchedulesWrite,
				ScopeStatementsRead, ScopeNotificationsRead,
				ScopeMFAWrite, ScopeSessionWrite, ScopeCredentialWrite, ScopeOAuthAuthorise,
				ScopeKYCRead, ScopeKYCWrite, ScopeKYCReview, ScopeKYCDecide,
				ScopeRiskReview, ScopeRiskDecide,
				ScopeFeesAdmin, ScopeJobsRead, ScopeAuditRead,
			} {
				scopeSet[s] = struct{}{}
			}
		case RoleRiskAnalyst:
			for _, s := range []string{
				ScopeKYCReview, ScopeKYCDecide,
				ScopeRiskReview, ScopeRiskDecide,
				ScopeTransfersRead, ScopeAuditRead,
			} {
				scopeSet[s] = struct{}{}
			}
		case RoleReadonly:
			for _, s := range []string{
				ScopeProfileRead, ScopeAccountsRead, ScopeTransfersRead,
				ScopeCardsRead, ScopeSavingsRead, ScopeSchedulesRead,
				ScopeStatementsRead, ScopeKYCRead, ScopeRiskReview,
				ScopeJobsRead, ScopeAuditRead,
			} {
				scopeSet[s] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(scopeSet))
	for s := range scopeSet {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

// HasRole checks whether a specific role is present within a list of roles.
func HasRole(roles []string, targetRole string) bool {
	for _, r := range roles {
		if r == targetRole {
			return true
		}
	}
	return false
}

// HasAnyRole checks whether at least one of the target roles is present within the user's roles.
func HasAnyRole(userRoles []string, targetRoles ...string) bool {
	for _, target := range targetRoles {
		for _, r := range userRoles {
			if r == target {
				return true
			}
		}
	}
	return false
}

// HasScope checks whether a specific scope is present within a list of scopes.
func HasScope(scopes []string, targetScope string) bool {
	for _, s := range scopes {
		if s == targetScope {
			return true
		}
	}
	return false
}

// HasAllScopes checks whether all required scopes are present in the granted scopes slice.
func HasAllScopes(grantedScopes []string, requiredScopes ...string) bool {
	if len(requiredScopes) == 0 {
		return true
	}
	for _, required := range requiredScopes {
		found := false
		for _, granted := range grantedScopes {
			if granted == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// HasAnyScope checks whether at least one required scope is present in the granted scopes slice.
func HasAnyScope(grantedScopes []string, requiredScopes ...string) bool {
	if len(requiredScopes) == 0 {
		return true
	}
	for _, required := range requiredScopes {
		for _, granted := range grantedScopes {
			if granted == required {
				return true
			}
		}
	}
	return false
}
