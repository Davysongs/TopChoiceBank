package platformhttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
)

func Run(ctx context.Context, address string, handler http.Handler, shutdownTimeout time.Duration, logger *logging.Logger) error {
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout:  5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		DisableKeepAlives: false,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server starting", "address", address)
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		logger.Info("http server shutdown complete")

		shutdownErr := <-errCh
		if shutdownErr != nil && !errors.Is(shutdownErr, http.ErrServerClosed) {
			return shutdownErr
		}
		return nil
	}
}

