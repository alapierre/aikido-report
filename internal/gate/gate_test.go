package gate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
)

// fakeAPI implements ContainerAPI and RepositoryAPI with pluggable
// behavior per test.
type fakeAPI struct {
	listContainers   func(ctx context.Context, name string) ([]publicapi.Container, error)
	getContainer     func(ctx context.Context, id int) (publicapi.Container, error)
	triggerContainer func(ctx context.Context, id int) error
	listCodeRepos    func(ctx context.Context, name string) ([]publicapi.CodeRepo, error)
	getCodeRepo      func(ctx context.Context, id int) (publicapi.CodeRepo, error)
	triggerCodeRepo  func(ctx context.Context, id int, types publicapi.ScanTypes) error
	exportIssues     func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error)
}

var errUnexpectedCall = errors.New("unexpected API call")

// The real client must satisfy both consumer-side interfaces.
var (
	_ ContainerAPI  = (*publicapi.Client)(nil)
	_ RepositoryAPI = (*publicapi.Client)(nil)
)

func (f *fakeAPI) ListContainers(ctx context.Context, name string) ([]publicapi.Container, error) {
	if f.listContainers == nil {
		return nil, errUnexpectedCall
	}
	return f.listContainers(ctx, name)
}

func (f *fakeAPI) GetContainer(ctx context.Context, id int) (publicapi.Container, error) {
	if f.getContainer == nil {
		return publicapi.Container{}, errUnexpectedCall
	}
	return f.getContainer(ctx, id)
}

func (f *fakeAPI) TriggerContainerScan(ctx context.Context, id int) error {
	if f.triggerContainer == nil {
		return errUnexpectedCall
	}
	return f.triggerContainer(ctx, id)
}

func (f *fakeAPI) ListCodeRepos(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
	if f.listCodeRepos == nil {
		return nil, errUnexpectedCall
	}
	return f.listCodeRepos(ctx, name)
}

func (f *fakeAPI) GetCodeRepo(ctx context.Context, id int) (publicapi.CodeRepo, error) {
	if f.getCodeRepo == nil {
		return publicapi.CodeRepo{}, errUnexpectedCall
	}
	return f.getCodeRepo(ctx, id)
}

func (f *fakeAPI) TriggerCodeRepoScan(ctx context.Context, id int, types publicapi.ScanTypes) error {
	if f.triggerCodeRepo == nil {
		return errUnexpectedCall
	}
	return f.triggerCodeRepo(ctx, id, types)
}

func (f *fakeAPI) ExportOpenIssues(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
	if f.exportIssues == nil {
		return nil, errUnexpectedCall
	}
	return f.exportIssues(ctx, filter)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// instantSleep never waits and never fails; polling loops spin freely.
func instantSleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

// sleepCancellingAfter returns a SleepFunc that succeeds n times and then
// cancels the given context, simulating an operation timeout during a wait.
func sleepCancellingAfter(n int, cancel context.CancelFunc) SleepFunc {
	count := 0
	return func(ctx context.Context, d time.Duration) error {
		count++
		if count > n {
			cancel()
		}
		return ctx.Err()
	}
}

func TestPollUntilChecksBeforeSleeping(t *testing.T) {
	sleeps := 0
	sleep := func(ctx context.Context, d time.Duration) error {
		sleeps++
		return nil
	}
	calls := 0
	err := pollUntil(t.Context(), sleep, time.Second, func(ctx context.Context) (bool, error) {
		calls++
		return calls == 3, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || sleeps != 2 {
		t.Errorf("calls=%d sleeps=%d, want 3 and 2", calls, sleeps)
	}
}

func TestPollUntilPropagatesCheckError(t *testing.T) {
	boom := errors.New("boom")
	err := pollUntil(t.Context(), instantSleep, time.Second, func(ctx context.Context) (bool, error) {
		return false, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want boom", err)
	}
}
