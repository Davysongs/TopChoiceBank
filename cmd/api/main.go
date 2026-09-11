package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Davysongs/TopChoiceBank/internal/platform/config"
	platformdb "github.com/Davysongs/TopChoiceBank/internal/platform/database"
	platformhttp "github.com/Davysongs/TopChoiceBank/internal/platform/http"
	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	logger := logging.New(cfg.LogLevel)
	logger.Info("starting TopChoiceBank v2 API", "environment", cfg.AppEnvironment)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

		db, err := platformdb.NewPool(platformdb.Config{
		DSN:             cfg.DatabaseURL,
		MaxOpenConns:    cfg.DatabaseMaxOpenConns,
		MaxIdleConns:    cfg.DatabaseMaxIdleConns,
		ConnMaxLifetime: cfg.DatabaseConnMaxLifetime,
	})
	if err != nil {
		if cfg.DatabaseAutoMigrate {
			logger.Error("database pool initialization failed and auto-migrate is enabled", err)
			os.Exit(1)
		}
		logger.Warn("database pool not initialized yet", "error", err)
	} else {
		if cfg.DatabaseAutoMigrate {
			if err := platformdb.ApplyIdentityBootstrapMigrations(ctx, db); err != nil {
				logger.Error("identity bootstrap migration failed", err)
				os.Exit(1)
			}
		}
		defer platformdb.Shutdown(context.Background(), db)
	}

	router := platformhttp.NewRouter()
	router.Use(platformhttp.RequestIDMiddleware())
	router.Use(platformhttp.RequestLoggerMiddleware(logger))
	platformhttp.RegisterHealthRoutes(router)

	if err := platformhttp.Run(
		ctx,
		cfg.HTTPAddress(),
		router.Handler(),
		cfg.ShutdownTimeout,
		logger,
	); err != nil {
		logger.Error("api process stopped with error", err)
		os.Exit(1)
	}

	logger.Info("api process stopped")
}
