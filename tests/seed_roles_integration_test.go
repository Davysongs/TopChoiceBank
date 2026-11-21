package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
)

// TestSeedRoles_GrantAndEnsureDefaultCustomerRole tests offline role grant functionality
// and default customer role backfill using actual CLI functions.
func TestSeedRoles_GrantAndEnsureDefaultCustomerRole(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	repo := identity.NewPostgresRepository(db)
	svc := identity.NewService(repo, "integration-test-jwt-secret-key-32bytes")

	// 1. User with no roles: EnsureDefaultCustomerRoles grants customer role
	emailNoRoles := fmt.Sprintf("seed_no_roles_%d@example.com", time.Now().UnixNano())
	regResp1, err := svc.Register(ctx, identity.RegisterRequest{
		Email:                emailNoRoles,
		Password:             "P@ssword1234!",
		AcceptedTermsVersion: "v1.0",
	})
	if err != nil {
		t.Fatalf("failed to register user 1: %v", err)
	}

	// Delete automatically granted roles so user has strictly no roles
	_, err = db.ExecContext(ctx, "DELETE FROM identity.user_roles WHERE user_id = $1", regResp1.UserID)
	if err != nil {
		t.Fatalf("failed to clear roles for user 1: %v", err)
	}

	assignedCount, err := identity.EnsureDefaultCustomerRoles(ctx, db)
	if err != nil {
		t.Fatalf("EnsureDefaultCustomerRoles failed: %v", err)
	}
	if assignedCount < 1 {
		t.Errorf("expected at least 1 role assigned for user without roles, got %d", assignedCount)
	}

	roles1, err := repo.GetUserRoles(ctx, regResp1.UserID)
	if err != nil {
		t.Fatalf("failed to get user 1 roles: %v", err)
	}
	if len(roles1) != 1 || roles1[0] != "customer" {
		t.Errorf("expected customer role for user 1, got %v", roles1)
	}

	// 2. User with an active admin role: EnsureDefaultCustomerRoles must NOT assign customer role
	emailAdmin := fmt.Sprintf("seed_admin_%d@example.com", time.Now().UnixNano())
	regResp2, err := svc.Register(ctx, identity.RegisterRequest{
		Email:                emailAdmin,
		Password:             "P@ssword1234!",
		AcceptedTermsVersion: "v1.0",
	})
	if err != nil {
		t.Fatalf("failed to register user 2: %v", err)
	}

	_, err = db.ExecContext(ctx, "DELETE FROM identity.user_roles WHERE user_id = $1", regResp2.UserID)
	if err != nil {
		t.Fatalf("failed to clear roles for user 2: %v", err)
	}

	if err := identity.GrantUserRole(ctx, db, emailAdmin, "admin", ""); err != nil {
		t.Fatalf("GrantUserRole failed: %v", err)
	}

	// Run EnsureDefaultCustomerRoles again
	_, err = identity.EnsureDefaultCustomerRoles(ctx, db)
	if err != nil {
		t.Fatalf("EnsureDefaultCustomerRoles failed: %v", err)
	}

	roles2, err := repo.GetUserRoles(ctx, regResp2.UserID)
	if err != nil {
		t.Fatalf("failed to get user 2 roles: %v", err)
	}
	if len(roles2) != 1 || roles2[0] != "admin" {
		t.Errorf("expected only admin role for user 2 (customer must be skipped), got %v", roles2)
	}

	// 3. User with revoked customer role: EnsureDefaultCustomerRoles reactivates customer role
	_, err = db.ExecContext(ctx, "UPDATE identity.user_roles SET revoked_at = clock_timestamp() WHERE user_id = $1", regResp1.UserID)
	if err != nil {
		t.Fatalf("failed to revoke user 1 customer role: %v", err)
	}

	rolesRevoked, err := repo.GetUserRoles(ctx, regResp1.UserID)
	if err != nil {
		t.Fatalf("failed to get user 1 roles after revoke: %v", err)
	}
	if len(rolesRevoked) != 0 {
		t.Errorf("expected 0 active roles for user 1, got %v", rolesRevoked)
	}

	_, err = identity.EnsureDefaultCustomerRoles(ctx, db)
	if err != nil {
		t.Fatalf("EnsureDefaultCustomerRoles failed on reactivate: %v", err)
	}

	rolesReactivated, err := repo.GetUserRoles(ctx, regResp1.UserID)
	if err != nil {
		t.Fatalf("failed to get user 1 roles after reactivate: %v", err)
	}
	if len(rolesReactivated) != 1 || rolesReactivated[0] != "customer" {
		t.Errorf("expected reactivated customer role for user 1, got %v", rolesReactivated)
	}

	// 4. Grant risk_analyst role via GrantUserRole with an administrator user ID
	if err := identity.GrantUserRole(ctx, db, emailNoRoles, "risk_analyst", regResp2.UserID); err != nil {
		t.Fatalf("GrantUserRole for risk_analyst failed: %v", err)
	}

	rolesMulti, err := repo.GetUserRoles(ctx, regResp1.UserID)
	if err != nil {
		t.Fatalf("failed to get user 1 multi-roles: %v", err)
	}
	if len(rolesMulti) != 2 {
		t.Errorf("expected 2 roles for user 1, got %v", rolesMulti)
	}
}
