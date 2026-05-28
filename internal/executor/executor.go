// Package executor turns a claimed job into a JobOutcome.
//
// Today the only implementation is NoOp: it acknowledges the job and
// reports success without doing real work. The real ProviderExecutor
// (interpret payload → call core/providers GetValue + PutValue → return
// status + version + checksum) lands in a follow-up issue where the
// sync_job payload schema gets locked down.
//
// Keeping this as an interface lets the agent's main loop be tested
// without provider SDKs and lets a future PR swap in real execution
// without touching the loop logic.
package executor

import (
	"context"
	"time"

	"github.com/secrets-bridge/agent/internal/client"
)

// Executor turns a claimed Job into a JobOutcome. Implementations MUST:
//   - respect ctx cancellation (graceful shutdown drains via ctx)
//   - never log or include secret values in the returned error
//   - return JobOutcome.Status = StatusSucceeded or StatusFailed
type Executor interface {
	Execute(ctx context.Context, job *client.Job) client.JobOutcome
}

// NoOp is the placeholder executor used until provider integration
// lands. It "executes" by waiting briefly so the loop and CP audit
// trail look realistic in dev — a future PR replaces this with the
// real ProviderExecutor.
type NoOp struct {
	// Delay simulates a tiny amount of work; defaults to 50ms.
	Delay time.Duration
}

// Execute returns a succeeded outcome after Delay (or context expiry).
func (n NoOp) Execute(ctx context.Context, _ *client.Job) client.JobOutcome {
	d := n.Delay
	if d <= 0 {
		d = 50 * time.Millisecond
	}
	select {
	case <-ctx.Done():
		return client.JobOutcome{Status: client.StatusFailed, Error: "cancelled"}
	case <-time.After(d):
		return client.JobOutcome{Status: client.StatusSucceeded}
	}
}
