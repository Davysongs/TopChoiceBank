package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAPIHost                  = "0.0.0.0"
	defaultAPIPort                  = "8080"
	defaultLogLevel                 = "info"
	defaultShutdownTimeoutInSeconds = 10
	defaultDatabaseMaxOpenConns     = 25
	defaultDatabaseMaxIdleConns     = 5
	defaultDatabaseConnLifetime     = 5 * time.Minute
)

type Config struct {
	AppEnvironment          string
	APIHost                 string
	APIPort                 string
	LogLevel                string
	ShutdownTimeout         time.Duration
	DatabaseURL             string
	DatabaseMaxOpenConns    int
	DatabaseMaxIdleConns    int
	DatabaseConnMaxLifetime time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		AppEnvironment:          getEnv("APP_ENV", "development"),
		APIHost:                 getEnv("API_HOST", defaultAPIHost),
		APIPort:                 getEnv("API_PORT", defaultAPIPort),
		LogLevel:                strings.ToLower(getEnv("LOG_LEVEL", defaultLogLevel)),
		ShutdownTimeout:         time.Duration(getInt("SHUTDOWN_TIMEOUT_SECONDS", defaultShutdownTimeoutInSeconds)) * time.Second,
		DatabaseURL:             getEnv("DATABASE_URL", ""),
		DatabaseMaxOpenConns:    getInt("DATABASE_MAX_OPEN_CONNS", defaultDatabaseMaxOpenConns),
		DatabaseMaxIdleConns:    getInt("DATABASE_MAX_IDLE_CONNS", defaultDatabaseMaxIdleConns),
		DatabaseConnMaxLifetime: time.Second * time.Duration(getInt("DATABASE_CONN_MAX_LIFETIME_SECONDS", int(defaultDatabaseConnLifetime.Seconds()))),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("missing required DATABASE_URL")
	}
	if _, err := strconv.Atoi(cfg.APIPort); err != nil {
		return Config{}, fmt.Errorf("invalid API_PORT: %w", err)
	}

	return cfg, nil
}

func (c Config) HTTPAddress() string {
	return fmt.Sprintf("%s:%s", c.APIHost, c.APIPort)
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
