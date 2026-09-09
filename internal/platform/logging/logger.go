package logging

import (
	"log/slog"
	"os"
	"strings"
)

type Logger struct {
	logger *slog.Logger
}

func New(level string) *Logger {
	parsed := parseLevel(level)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parsed,
	})
	return &Logger{
		logger: slog.New(handler),
	}
}

func parseLevel(level string) *slog.LevelVar {
	lvl := new(slog.LevelVar)
	switch strings.ToLower(level) {
	case "debug":
		lvl.Set(slog.LevelDebug)
	case "warn":
		lvl.Set(slog.LevelWarn)
	case "error":
		lvl.Set(slog.LevelError)
	default:
		lvl.Set(slog.LevelInfo)
	}
	return lvl
}

func (l *Logger) With(fields ...any) *Logger {
	return &Logger{logger: l.logger.With(fields...)}
}

func (l *Logger) WithRequestID(requestID string) *Logger {
	return l.With("request_id", requestID)
}

func (l *Logger) Info(message string, args ...any) {
	l.logger.Info(message, args...)
}

func (l *Logger) Debug(message string, args ...any) {
	l.logger.Debug(message, args...)
}

func (l *Logger) Warn(message string, args ...any) {
	l.logger.Warn(message, args...)
}

func (l *Logger) Error(message string, err error, args ...any) {
	merged := append([]any{"error", err}, args...)
	l.logger.Error(message, merged...)
}

