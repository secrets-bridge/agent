package executor

import (
	"context"

	"github.com/secrets-bridge/agent/internal/client"
)

// Router dispatches a job to the right Executor based on job_type.
// Unknown types fall through to Default — which is NoOp in production
// today, letting heartbeat-style or sentinel jobs flow through the
// claim/complete loop without provider integration.
type Router struct {
	ByType  map[string]Executor
	Default Executor
}

// Execute selects the per-type executor when one is registered.
func (r Router) Execute(ctx context.Context, job *client.Job) client.JobOutcome {
	if e, ok := r.ByType[job.JobType]; ok {
		return e.Execute(ctx, job)
	}
	if r.Default != nil {
		return r.Default.Execute(ctx, job)
	}
	return client.JobOutcome{
		Status: client.StatusFailed,
		Error:  "no executor registered for job_type=" + job.JobType,
	}
}
