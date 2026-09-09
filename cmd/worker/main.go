package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/platform/config"
	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	logger := logging.New(cfg.LogLevel)
	logger.Info("starting TopChoiceBank v2 worker process", "environment", cfg.AppEnvironment)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	logger.Info("worker shutdown requested", "timeout", cfg.ShutdownTimeout)
	<-shutdownCtx.Done()
	logger.Info("worker process stopped")
}

