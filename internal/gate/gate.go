// Package gate implements the two use cases of this tool: the container
// deployment gate and the repository release gate. Each service resolves
// its scan target in Aikido, optionally triggers a scan, waits for the
// expected result, fetches open findings and returns a domain
// report.Report. Neither service knows about SARIF, exit codes, or CLI
// flags.
package gate

import (
	"context"
	"errors"
	"time"
)

// SleepFunc waits for the given duration or until the context is done.
// It is injectable so polling is testable without real delays.
type SleepFunc func(ctx context.Context, d time.Duration) error

// defaultSleep waits on a timer, honoring context cancellation.
func defaultSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// defaultPollInterval keeps polling well under the Aikido rate limit of
// 20 requests per minute per workspace.
const defaultPollInterval = 15 * time.Second

// Sentinel errors for the distinct gate failure modes. All are technical
// errors (CLI exit code 1), but callers and tests can classify them with
// errors.Is.
var (
	// ErrNoRepository means no Aikido repository matched the requested target.
	ErrNoRepository = errors.New("no matching Aikido repository")
	// ErrAmbiguousMatch means more than one Aikido repository matched and
	// the tool refuses to pick one arbitrarily.
	ErrAmbiguousMatch = errors.New("ambiguous match")
	// ErrEmptyRepository means the matched container repository holds no image.
	ErrEmptyRepository = errors.New("repository is empty")
	// ErrScanNotReady means the expected scan result does not exist and
	// waiting was disabled.
	ErrScanNotReady = errors.New("scan result not available")
	// ErrScanTimeout means the expected scan result did not appear within
	// the operation timeout.
	ErrScanTimeout = errors.New("timed out waiting for scan")
	// ErrBranchMismatch means Aikido is configured to scan a different
	// branch than the one requested.
	ErrBranchMismatch = errors.New("branch mismatch")
	// ErrInactiveRepository means a scan cannot be triggered because the
	// repository is inactive in Aikido.
	ErrInactiveRepository = errors.New("repository is inactive")
)

// pollUntil repeatedly evaluates check, sleeping interval between
// attempts, until check reports done, check fails, or the context ends
// (typically via the operation timeout).
func pollUntil(ctx context.Context, sleep SleepFunc, interval time.Duration, check func(ctx context.Context) (bool, error)) error {
	if interval <= 0 {
		interval = defaultPollInterval
	}
	for {
		done, err := check(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if err := sleep(ctx, interval); err != nil {
			return err
		}
	}
}
