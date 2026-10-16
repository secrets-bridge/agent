// Package executor turns a claimed job into a JobOutcome.
//
// Router dispatches by job_type to PatchExecutor, ReadExecutor and
// DiscoverExecutor. Keeping Executor as an interface lets the agent's main
// loop be tested without provider SDKs.
package executor

import (
	"context"

	"github.com/secrets-bridge/agent/internal/client"
)

// Executor turns a claimed Job into a JobOutcome. Implementations MUST:
//   - respect ctx cancellation (graceful shutdown drains via ctx)
//   - never log or include secret values in the returned error
//   - return JobOutcome.Status = StatusSucceeded or StatusFailed
type Executor interface {
	Execute(ctx context.Context, job *client.Job) client.JobOutcome
}
