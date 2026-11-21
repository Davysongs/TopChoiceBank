package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/platform/config"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
)

// main is an offline CLI command to seed initial role grants to user accounts.
func main() {
	emailFlag := flag.String("email", "", "User email address to assign role")
	roleFlag := flag.String("role", "customer", "Role name to grant (customer, admin, risk_analyst, readonly)")
	grantedByFlag := flag.String("granted-by", "", "Optional user ID of granting administrator")
	ensureDefaultsFlag := flag.Bool("ensure-customer-defaults", false, "Assign default customer role to all users without active roles")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	logger := logging.New(cfg.LogLevel)

	db, err := platformdb.NewPool(platformdb.Config{
		DSN:             cfg.DatabaseURL,
		MaxOpenConns:    cfg.DatabaseMaxOpenConns,
		MaxIdleConns:    cfg.DatabaseMaxIdleConns,
		ConnMaxLifetime: cfg.DatabaseConnMaxLifetime,
	})
	if err != nil {
		logger.Error("failed to connect to database", err)
		os.Exit(1)
	}
	defer platformdb.Shutdown(context.Background(), db)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if *ensureDefaultsFlag {
		count, err := ensureDefaultCustomerRoles(ctx, db)
		if err != nil {
			logger.Error("failed to assign default customer roles", err)
			os.Exit(1)
		}
		logger.Info("default customer role verification complete", "assigned_count", count)
		return
	}

	email := strings.TrimSpace(*emailFlag)
	roleName := strings.TrimSpace(*roleFlag)
	if email == "" {
		fmt.Fprintln(os.Stderr, "error: -email flag is required when not using -ensure-customer-defaults")
		flag.Usage()
		os.Exit(1)
	}

	if err := grantUserRole(ctx, db, email, roleName, strings.TrimSpace(*grantedByFlag)); err != nil {
		logger.Error("failed to grant role", err, "email", email, "role", roleName)
		os.Exit(1)
	}

	logger.Info("role successfully granted", "email", email, "role", roleName)
}

// grantUserRole assigns a specified role to a user identified by email.
func grantUserRole(ctx context.Context, db *sql.DB, email, roleName, grantedBy string) error {
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

	var grantedByVal any
	if grantedBy != "" {
		grantedByVal = grantedBy
	}

	query := `
		INSERT INTO identity.user_roles (user_id, role_id, granted_by, granted_at, revoked_at)
		VALUES ($1, $2, $3, clock_timestamp(), NULL)
		ON CONFLICT (user_id, role_id)
		DO UPDATE SET revoked_at = NULL, granted_at = clock_timestamp(), granted_by = EXCLUDED.granted_by
	`
	_, err = db.ExecContext(ctx, query, userID, roleID, grantedByVal)
	if err != nil {
		return fmt.Errorf("failed to insert user role grant: %w", err)
	}

	return nil
}

// ensureDefaultCustomerRoles ensures every registered user has at least the 'customer' role
// if they do not already possess any active roles.
func ensureDefaultCustomerRoles(ctx context.Context, db *sql.DB) (int64, error) {
	query := `
		INSERT INTO identity.user_roles (user_id, role_id, granted_at)
		SELECT u.id, r.id, clock_timestamp()
		FROM identity.users u
		CROSS JOIN identity.roles r
		WHERE r.name = 'customer'
		  AND NOT EXISTS (
			  SELECT 1 FROM identity.user_roles ur
			  JOIN identity.roles r2 ON ur.role_id = r2.id
			  WHERE ur.user_id = u.id AND r2.name = 'customer' AND ur.revoked_at IS NULL
		  )
		ON CONFLICT (user_id, role_id) DO UPDATE SET revoked_at = NULL
	`
	res, err := db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
