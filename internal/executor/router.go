package executor

import (
	"context"
	"fmt"

	"github.com/secrets-bridge/agent/internal/client"
)

// Router dispatches a job to the right Executor based on job_type.
// There is no default: a job type this agent does not implement is
// reported as failed, never as a silent success (AGT-N-06). Reporting
// success for work that never ran would let the CP mark a request
// executed when nothing happened.
type Router struct {
	ByType map[string]Executor
}

// Execute selects the per-type executor, or fails the job.
func (r Router) Execute(ctx context.Context, job *client.Job) client.JobOutcome {
	if e, ok := r.ByType[job.JobType]; ok {
		return e.Execute(ctx, job)
	}
	return client.JobOutcome{
		Status: client.StatusFailed,
		Error:  fmt.Sprintf("unsupported job type %q", job.JobType),
	}
}
