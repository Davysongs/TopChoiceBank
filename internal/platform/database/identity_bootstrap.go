package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func ApplyIdentityBootstrapMigrations(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("database pool is required")
	}

	return applyMigrationsFromEmbeddedFiles(ctx, db, "0001_identity_bootstrap", migrationFiles)
}

func applyMigrationsFromEmbeddedFiles(ctx context.Context, db *sql.DB, prefix string, source fs.FS) error {
	entries, err := fs.ReadDir(source, "migrations")
	if err != nil {
		return err
	}

	eligible := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".sql") {
			eligible = append(eligible, name)
		}
	}
	if len(eligible) == 0 {
		return fmt.Errorf("no migration files found for %q", prefix)
	}
	sort.Strings(eligible)

	for _, name := range eligible {
		contents, readErr := fs.ReadFile(source, name)
		if readErr != nil {
			return readErr
		}

		if _, execErr := db.ExecContext(ctx, string(contents)); execErr != nil {
			return execErr
		}
	}

	return nil
}
