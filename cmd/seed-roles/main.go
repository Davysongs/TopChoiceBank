package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/identity"
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
		count, err := identity.EnsureDefaultCustomerRoles(ctx, db)
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

	if err := identity.GrantUserRole(ctx, db, email, roleName, strings.TrimSpace(*grantedByFlag)); err != nil {
		logger.Error("failed to grant role", err, "email", email, "role", roleName)
		os.Exit(1)
	}

	logger.Info("role successfully granted", "email", email, "role", roleName)
}
