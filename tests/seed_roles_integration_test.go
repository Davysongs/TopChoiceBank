package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
)

// TestSeedRoles_GrantAndEnsureDefaultCustomerRole tests offline role grant functionality.
func TestSeedRoles_GrantAndEnsureDefaultCustomerRole(t *testing.T) {
	server, db := setupTestServer(t)
	defer server.Close()
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	repo := identity.NewPostgresRepository(db)
	svc := identity.NewService(repo, "integration-test-jwt-secret-key-32bytes")

	email := fmt.Sprintf("seed_role_%d@example.com", time.Now().UnixNano())
	regResp, err := svc.Register(ctx, identity.RegisterRequest{
		Email:                email,
		Password:             "P@ssword1234!",
		AcceptedTermsVersion: "v1.0",
	})
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}

	// 1. Verify granting admin role
	var adminRoleID int16
	err = db.QueryRowContext(ctx, "SELECT id FROM identity.roles WHERE name = 'admin'").Scan(&adminRoleID)
	if err != nil {
		t.Fatalf("failed to query admin role id: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO identity.user_roles (user_id, role_id, granted_at)
		VALUES ($1, $2, clock_timestamp())
		ON CONFLICT (user_id, role_id) DO UPDATE SET revoked_at = NULL
	`, regResp.UserID, adminRoleID)
	if err != nil {
		t.Fatalf("failed to grant admin role: %v", err)
	}

	// Verify user has admin role
	var hasAdmin bool
	err = db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM identity.user_roles ur
			JOIN identity.roles r ON ur.role_id = r.id
			WHERE ur.user_id = $1 AND r.name = 'admin' AND ur.revoked_at IS NULL
		)
	`, regResp.UserID).Scan(&hasAdmin)
	if err != nil || !hasAdmin {
		t.Fatalf("expected active admin role for user: %v", err)
	}

	// 2. Ensure default customer role grants customer role
	var customerRoleID int16
	err = db.QueryRowContext(ctx, "SELECT id FROM identity.roles WHERE name = 'customer'").Scan(&customerRoleID)
	if err != nil {
		t.Fatalf("failed to query customer role id: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO identity.user_roles (user_id, role_id, granted_at)
		VALUES ($1, $2, clock_timestamp())
		ON CONFLICT (user_id, role_id) DO UPDATE SET revoked_at = NULL
	`, regResp.UserID, customerRoleID)
	if err != nil {
		t.Fatalf("failed to grant customer role: %v", err)
	}

	var hasCustomer bool
	err = db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM identity.user_roles ur
			JOIN identity.roles r ON ur.role_id = r.id
			WHERE ur.user_id = $1 AND r.name = 'customer' AND ur.revoked_at IS NULL
		)
	`, regResp.UserID).Scan(&hasCustomer)
	if err != nil || !hasCustomer {
		t.Fatalf("expected active customer role for user: %v", err)
	}
}
