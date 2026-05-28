package executor_test

import (
	"context"
	"testing"
	"time"

	"github.com/secrets-bridge/agent/internal/client"
	"github.com/secrets-bridge/agent/internal/executor"
)

func TestNoOp_ReturnsSucceeded(t *testing.T) {
	e := executor.NoOp{Delay: 5 * time.Millisecond}
	out := e.Execute(t.Context(), &client.Job{ID: "x"})
	if out.Status != client.StatusSucceeded {
		t.Fatalf("status: %q want %q", out.Status, client.StatusSucceeded)
	}
}

func TestNoOp_HonorsContextCancellation(t *testing.T) {
	e := executor.NoOp{Delay: 5 * time.Second}
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // pre-cancelled
	out := e.Execute(ctx, &client.Job{ID: "x"})
	if out.Status != client.StatusFailed {
		t.Fatalf("status under cancellation: %q", out.Status)
	}
	if out.Error == "" {
		t.Fatal("expected an error message on cancelled execution")
	}
}
