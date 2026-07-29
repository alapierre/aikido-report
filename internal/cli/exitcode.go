package cli

import (
	"fmt"

	"github.com/alapierre/aikido-report/internal/report"
)

// ExitCodeError signals a failed quality gate. Main unwraps it with
// errors.As and uses Code as the process exit code, distinguishing gate
// failures (default 2) from technical errors (always 1).
type ExitCodeError struct {
	Code    int
	Message string
}

func (e *ExitCodeError) Error() string { return e.Message }

// evaluateGate checks the report against the gate threshold. An empty
// threshold disables the gate. The report has already been written when
// this runs.
func evaluateGate(rep report.Report, threshold report.Severity, exitCode int) error {
	if threshold == "" {
		return nil
	}
	count := rep.CountAtLeast(threshold)
	if count == 0 {
		return nil
	}
	return &ExitCodeError{
		Code:    exitCode,
		Message: fmt.Sprintf("quality gate failed: %d open finding(s) at or above %s severity", count, threshold),
	}
}
