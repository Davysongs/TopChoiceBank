package platformhttp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
)

type requestIDKeyType string

const requestIDKey requestIDKeyType = "request_id"

func RequestIDMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			requestID := req.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = generateRequestID()
				req.Header.Set("X-Request-ID", requestID)
			}
			ctx := req.Context().WithValue(requestIDKey, requestID)
			next.ServeHTTP(writer, req.WithContext(ctx))
			writer.Header().Set("X-Request-ID", requestID)
		})
	}
}

func RequestLoggerMiddleware(logger *logging.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			requestID := requestIDFromContext(req.Context())
			start := time.Now()

			logger.With("request_id", requestID, "method", req.Method, "path", req.URL.Path).Info("request started")

			response := &statusResponseWriter{
				ResponseWriter: writer,
				statusCode:     http.StatusOK,
			}
			next.ServeHTTP(response, req)

			logger.With(
				"request_id", requestID,
				"method", req.Method,
				"path", req.URL.Path,
				"status", response.statusCode,
				"duration_ms", time.Since(start).Milliseconds(),
				"bytes", response.written,
			).Info("request completed")
		})
	}
}

func requestIDFromContext(ctx context.Context) string {
	value := ctx.Value(requestIDKey)
	if value == nil {
		return ""
	}
	valueStr, ok := value.(string)
	if !ok {
		return ""
	}
	return valueStr
}

func generateRequestID() string {
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.statusCode = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(payload []byte) (int, error) {
	n, err := w.ResponseWriter.Write(payload)
	w.written += n
	return n, err
}

