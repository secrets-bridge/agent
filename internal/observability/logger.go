// Package observability provides the agent's structured logger.
package observability

import (
	"io"
	"log/slog"
	"strings"
)

// NewLogger returns a JSON structured logger writing to w (stderr in the
// binary).
func NewLogger(w io.Writer, levelStr string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: parseLevel(levelStr)})
	return slog.New(h).With("service", "secrets-bridge-agent")
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
