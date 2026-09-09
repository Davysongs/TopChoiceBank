package platformhttp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Davysongs/TopChoiceBank/internal/platform/logging"
	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
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
			ctx := req.Context()
			ctx = req.Context().WithValue(requestIDKey, requestID)
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

func WriteJSON(writer http.ResponseWriter, status int, value any) error {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func ParseIntQuery(r *http.Request, key string, fallback int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func IsNilResponseWriter(writer http.ResponseWriter) error {
	if writer == nil {
		return errors.New("writer is nil")
	}
	return nil
}

func constantTimeCompare(a, b string) bool {
	return security.ConstantTimeCompare(a, b)
}

