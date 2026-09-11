package config

import (
	"testing"
)

func TestLoad_DefaultsAndRequiredValues(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://topchoicebank:topchoicebank@localhost:5432/topchoicebank?sslmode=disable")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if cfg.AppEnvironment == "" {
		t.Fatal("AppEnvironment must be set")
	}
	if cfg.APIPort != "8080" {
		t.Fatalf("expected default APIPort 8080, got %s", cfg.APIPort)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected default LogLevel info, got %s", cfg.LogLevel)
	}
	if cfg.DatabaseURL == "" {
		t.Fatal("database url should not be empty")
	}
	if cfg.DatabaseAutoMigrate {
		t.Fatal("DatabaseAutoMigrate should be false by default")
	}
}
