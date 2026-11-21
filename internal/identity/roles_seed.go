package identity

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// GrantUserRole assigns a specified role to a user identified by email.
func GrantUserRole(ctx context.Context, db *sql.DB, email, roleName, grantedBy string) error {
	var userID string
	err := db.QueryRowContext(ctx, "SELECT id FROM identity.users WHERE email = $1", strings.ToLower(email)).Scan(&userID)
	if err != nil {
		return fmt.Errorf("user not found for email %q: %w", email, err)
	}

	var roleID int16
	err = db.QueryRowContext(ctx, "SELECT id FROM identity.roles WHERE name = $1", roleName).Scan(&roleID)
	if err != nil {
		return fmt.Errorf("role %q not found: %w", roleName, err)
	}

	query := `
		INSERT INTO identity.user_roles (user_id, role_id, granted_by, granted_at, revoked_at)
		VALUES ($1, $2, NULLIF($3, '')::uuid, clock_timestamp(), NULL)
		ON CONFLICT (user_id, role_id)
		DO UPDATE SET revoked_at = NULL, granted_at = clock_timestamp(), granted_by = EXCLUDED.granted_by
	`
	_, err = db.ExecContext(ctx, query, userID, roleID, strings.TrimSpace(grantedBy))
	if err != nil {
		return fmt.Errorf("failed to insert user role grant: %w", err)
	}

	return nil
}

// EnsureDefaultCustomerRoles ensures every registered user has at least the 'customer' role
// if they do not already possess any active roles.
func EnsureDefaultCustomerRoles(ctx context.Context, db *sql.DB) (int64, error) {
	query := `
		INSERT INTO identity.user_roles (user_id, role_id, granted_at)
		SELECT u.id, r.id, clock_timestamp()
		FROM identity.users u
		CROSS JOIN identity.roles r
		WHERE r.name = 'customer'
		  AND NOT EXISTS (
			  SELECT 1 FROM identity.user_roles ur
			  WHERE ur.user_id = u.id AND ur.revoked_at IS NULL
		  )
		ON CONFLICT (user_id, role_id) DO UPDATE SET revoked_at = NULL
	`
	res, err := db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
