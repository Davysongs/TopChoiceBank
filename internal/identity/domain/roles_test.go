package domain

import (
	"testing"
)

// TestRoleValidation checks that only allowed system roles are validated.
func TestRoleValidation(t *testing.T) {
	validRoles := []string{RoleCustomer, RoleAdmin, RoleRiskAnalyst, RoleReadonly}
	for _, r := range validRoles {
		if !IsValidRole(r) {
			t.Errorf("expected role %q to be valid", r)
		}
	}

	invalidRoles := []string{"", "superadmin", "guest", "operator", "root"}
	for _, r := range invalidRoles {
		if IsValidRole(r) {
			t.Errorf("expected role %q to be invalid", r)
		}
	}
}

// TestDefaultScopesForRoles verifies bundle mapping and segregation between roles.
func TestDefaultScopesForRoles(t *testing.T) {
	customerScopes := DefaultScopesForRoles([]string{RoleCustomer})
	if !HasScope(customerScopes, ScopeProfileRead) || !HasScope(customerScopes, ScopeTransfersWrite) {
		t.Errorf("customer should have profile:read and transfers:write")
	}
	if HasScope(customerScopes, ScopeAccountsAdmin) || HasScope(customerScopes, ScopeKYCDecide) {
		t.Errorf("customer must not have accounts:admin or kyc:decide")
	}

	riskScopes := DefaultScopesForRoles([]string{RoleRiskAnalyst})
	if !HasScope(riskScopes, ScopeKYCReview) || !HasScope(riskScopes, ScopeRiskDecide) {
		t.Errorf("risk_analyst should have kyc:review and risk:decide")
	}
	if HasScope(riskScopes, ScopeTransfersWrite) || HasScope(riskScopes, ScopeProfileWrite) {
		t.Errorf("risk_analyst must not have customer mutation scopes")
	}

	readonlyScopes := DefaultScopesForRoles([]string{RoleReadonly})
	if !HasScope(readonlyScopes, ScopeAccountsRead) || !HasScope(readonlyScopes, ScopeProfileRead) {
		t.Errorf("readonly should have read scopes")
	}
	if HasScope(readonlyScopes, ScopeProfileWrite) || HasScope(readonlyScopes, ScopeTransfersWrite) {
		t.Errorf("readonly must not have any write scopes")
	}

	adminScopes := DefaultScopesForRoles([]string{RoleAdmin})
	if !HasScope(adminScopes, ScopeAccountsAdmin) || !HasScope(adminScopes, ScopeTransfersReverse) {
		t.Errorf("admin should have administrative scopes")
	}
}

// TestRoleAndScopeHelpers verifies helper query functions.
func TestRoleAndScopeHelpers(t *testing.T) {
	roles := []string{RoleCustomer, RoleRiskAnalyst}
	if !HasRole(roles, RoleCustomer) || !HasRole(roles, RoleRiskAnalyst) {
		t.Error("expected true for existing roles")
	}
	if HasRole(roles, RoleAdmin) {
		t.Error("expected false for missing role")
	}

	if !HasAnyRole(roles, RoleAdmin, RoleCustomer) {
		t.Error("expected HasAnyRole to be true when one role matches")
	}
	if HasAnyRole(roles, RoleAdmin, RoleReadonly) {
		t.Error("expected HasAnyRole to be false when no roles match")
	}

	scopes := []string{ScopeProfileRead, ScopeAccountsRead}
	if !HasAllScopes(scopes, ScopeProfileRead) {
		t.Error("expected HasAllScopes to be true")
	}
	if HasAllScopes(scopes, ScopeProfileRead, ScopeProfileWrite) {
		t.Error("expected HasAllScopes to be false when one missing")
	}
	if !HasAnyScope(scopes, ScopeProfileWrite, ScopeAccountsRead) {
		t.Error("expected HasAnyScope to be true")
	}
}
