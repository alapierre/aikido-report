package gate

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
	"github.com/alapierre/aikido-report/internal/imageref"
	"github.com/alapierre/aikido-report/internal/report"
)

func mustRef(t *testing.T, image, tag string) imageref.Ref {
	t.Helper()
	ref, err := imageref.Parse(image, tag)
	if err != nil {
		t.Fatalf("Parse(%q, %q): %v", image, tag, err)
	}
	return ref
}

func containerService(api *fakeAPI) *ContainerService {
	return &ContainerService{API: api, Logger: testLogger(), Sleep: instantSleep}
}

var scannedContainer = publicapi.Container{
	ID: 101, Name: "application", RegistryName: "registry.example.com",
	LastScannedTag: "1.2.3", LastScannedAt: 1753700000, IsActive: true,
}

func TestContainerHappyPathTagAlreadyScanned(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			if name != "application" {
				t.Errorf("filter name = %q", name)
			}
			return []publicapi.Container{scannedContainer}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			if filter.ContainerRepoID != 101 {
				t.Errorf("filter = %+v", filter)
			}
			return []publicapi.Issue{
				{ID: 1, GroupID: 10, Type: "open_source", Severity: "critical", CVEID: "CVE-2025-1", AffectedPackage: "openssl"},
				{ID: 2, GroupID: 11, Type: "open_source", Severity: "low", CVEID: "CVE-2025-2", AffectedPackage: "zlib"},
			}, nil
		},
	}
	svc := containerService(api)
	rep, err := svc.Run(t.Context(), ContainerParams{
		Ref:              mustRef(t, "registry.example.com/team/application", "1.2.3"),
		DashboardBaseURL: "https://app.aikido.dev",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Target.Kind != report.TargetContainer || rep.Target.Name != "application" ||
		rep.Target.Registry != "registry.example.com" || rep.Target.Tag != "1.2.3" {
		t.Errorf("unexpected target: %+v", rep.Target)
	}
	if rep.Target.ReportURL != "https://app.aikido.dev/container/101" {
		t.Errorf("ReportURL = %q", rep.Target.ReportURL)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(rep.Findings))
	}
	if rep.Findings[0].Severity != report.SeverityCritical || rep.Findings[0].RuleID != "CVE-2025-1" {
		t.Errorf("unexpected finding: %+v", rep.Findings[0])
	}
}

// TestContainerDoesNotFilterByAttackSurface documents a deliberate
// asymmetry: unlike RepositoryService, ContainerService never drops
// findings by attack surface. No evidence has been observed of a
// container-scoped export returning code-repo-native findings (see
// TestRepositoryDropsContainerAttackSurface for the direction that is
// filtered).
func TestContainerDoesNotFilterByAttackSurface(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			return []publicapi.Container{scannedContainer}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return []publicapi.Issue{
				{ID: 1, GroupID: 1, Type: "open_source", Severity: "high", AttackSurface: "docker_container"},
				{ID: 2, GroupID: 2, Type: "open_source", Severity: "low", AttackSurface: "backend"},
			}, nil
		},
	}
	rep, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "registry.example.com/team/application", "1.2.3"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (no attack-surface filtering)", len(rep.Findings))
	}
}

func TestContainerNoFindings(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			return []publicapi.Container{scannedContainer}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
	}
	rep, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "application", "1.2.3"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("got %d findings, want 0", len(rep.Findings))
	}
}

func TestContainerNoRepositoryFound(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			return nil, nil
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "ghcr.io/org/missing", "1.0"),
	})
	if !errors.Is(err, ErrNoRepository) {
		t.Fatalf("got %v, want ErrNoRepository", err)
	}
}

func TestContainerRegistryMismatchExplained(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			return []publicapi.Container{
				{ID: 7, Name: "application", RegistryName: "other.example.com", IsActive: true},
			}, nil
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "registry.example.com/team/application", "1.0"),
	})
	if !errors.Is(err, ErrNoRepository) {
		t.Fatalf("got %v, want ErrNoRepository", err)
	}
	if !strings.Contains(err.Error(), "other.example.com") {
		t.Errorf("error should list seen registries, got: %v", err)
	}
}

func TestContainerRegistryNarrowsToOne(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			return []publicapi.Container{
				{ID: 1, Name: "application", RegistryName: "a.example.com", LastScannedTag: "1.0", LastScannedAt: 5, IsActive: true},
				{ID: 2, Name: "application", RegistryName: "B.EXAMPLE.COM", LastScannedTag: "1.0", LastScannedAt: 5, IsActive: true},
			}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			if filter.ContainerRepoID != 2 {
				t.Errorf("expected container 2, got %+v", filter)
			}
			return nil, nil
		},
	}
	// Registry comparison must be case-insensitive.
	if _, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "b.example.com/application", "1.0"),
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestContainerAmbiguousWithoutRegistry(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			return []publicapi.Container{
				{ID: 1, Name: "application", RegistryName: "a.example.com", IsActive: true},
				{ID: 2, Name: "application", RegistryName: "b.example.com", IsActive: true},
			}, nil
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "application", "1.0"),
	})
	if !errors.Is(err, ErrAmbiguousMatch) {
		t.Fatalf("got %v, want ErrAmbiguousMatch", err)
	}
	for _, part := range []string{"a.example.com", "b.example.com", "--image"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error should contain %q, got: %v", part, err)
		}
	}
}

func TestContainerFullPathNameMatch(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			// Aikido stores the name with its namespace here.
			return []publicapi.Container{
				{ID: 3, Name: "team/application", RegistryName: "registry.example.com",
					LastScannedTag: "1.2.3", LastScannedAt: 5, IsActive: true},
			}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
	}
	rep, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "registry.example.com/team/application", "1.2.3"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Target.Name != "team/application" {
		t.Errorf("Target.Name = %q", rep.Target.Name)
	}
}

func TestContainerEmptyRepository(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			return []publicapi.Container{{ID: 1, Name: "application", IsEmpty: true, IsActive: true}}, nil
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "application", "1.0"),
	})
	if !errors.Is(err, ErrEmptyRepository) {
		t.Fatalf("got %v, want ErrEmptyRepository", err)
	}
}

func TestContainerTriggerAndWaitForNewerScan(t *testing.T) {
	var triggers, polls atomic.Int32
	baseline := scannedContainer.LastScannedAt
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "1.2.2" // older tag scanned
			return []publicapi.Container{c}, nil
		},
		triggerContainer: func(ctx context.Context, id int) error {
			triggers.Add(1)
			return nil
		},
		getContainer: func(ctx context.Context, id int) (publicapi.Container, error) {
			c := scannedContainer
			if polls.Add(1) < 3 {
				// last_scanned_tag flips to the expected tag before
				// last_scanned_at actually moves past the baseline —
				// this must not be accepted as ready (see comment on
				// ensureTagScanned).
				c.LastScannedAt = baseline
			} else {
				c.LastScannedAt = baseline + 60
			}
			return c, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref:          mustRef(t, "registry.example.com/team/application", "1.2.3"),
		Wait:         true,
		TriggerScan:  true,
		PollInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if triggers.Load() != 1 {
		t.Errorf("scan triggered %d times, want exactly 1", triggers.Load())
	}
	if polls.Load() != 3 {
		t.Errorf("polled %d times, want 3 (a same-baseline last_scanned_at must not satisfy the wait)", polls.Load())
	}
}

func TestContainerWaitWithoutTrigger(t *testing.T) {
	var polls atomic.Int32
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = ""
			c.LastScannedAt = -1
			return []publicapi.Container{c}, nil
		},
		getContainer: func(ctx context.Context, id int) (publicapi.Container, error) {
			c := scannedContainer
			if polls.Add(1) < 2 {
				c.LastScannedTag = ""
				c.LastScannedAt = -1
			}
			return c, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
		// triggerContainer deliberately nil: a call would fail the test.
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref:  mustRef(t, "registry.example.com/team/application", "1.2.3"),
		Wait: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestContainerNoWaitScanNotReady(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "0.9.0"
			return []publicapi.Container{c}, nil
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "registry.example.com/team/application", "1.2.3"),
	})
	if !errors.Is(err, ErrScanNotReady) {
		t.Fatalf("got %v, want ErrScanNotReady", err)
	}
	if !strings.Contains(err.Error(), "0.9.0") {
		t.Errorf("error should mention last scanned tag, got: %v", err)
	}
}

func TestContainerTagComparisonIsCaseSensitive(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "V1.2.3" // different case than requested
			return []publicapi.Container{c}, nil
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref: mustRef(t, "registry.example.com/team/application", "v1.2.3"),
	})
	if !errors.Is(err, ErrScanNotReady) {
		t.Fatalf("got %v, want ErrScanNotReady (tags must compare case-sensitively)", err)
	}
}

func TestContainerDryRunNeverTriggers(t *testing.T) {
	var polls atomic.Int32
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "1.2.2"
			return []publicapi.Container{c}, nil
		},
		getContainer: func(ctx context.Context, id int) (publicapi.Container, error) {
			polls.Add(1)
			return scannedContainer, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
		// triggerContainer nil: any trigger call fails the run.
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref:         mustRef(t, "registry.example.com/team/application", "1.2.3"),
		Wait:        true,
		TriggerScan: true,
		DryRun:      true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestContainerInactiveCannotTrigger(t *testing.T) {
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "1.2.2"
			c.IsActive = false
			return []publicapi.Container{c}, nil
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref:         mustRef(t, "registry.example.com/team/application", "1.2.3"),
		Wait:        true,
		TriggerScan: true,
	})
	if !errors.Is(err, ErrInactiveRepository) {
		t.Fatalf("got %v, want ErrInactiveRepository", err)
	}
}

func TestContainerPollTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "1.2.2"
			return []publicapi.Container{c}, nil
		},
		getContainer: func(ctx context.Context, id int) (publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "1.2.2"
			return c, nil
		},
	}
	svc := &ContainerService{API: api, Logger: testLogger(), Sleep: sleepCancellingAfter(2, cancel)}
	_, err := svc.Run(ctx, ContainerParams{
		Ref:  mustRef(t, "registry.example.com/team/application", "1.2.3"),
		Wait: true,
	})
	if !errors.Is(err, ErrScanTimeout) {
		t.Fatalf("got %v, want ErrScanTimeout", err)
	}
	if !strings.Contains(err.Error(), "1.2.2") {
		t.Errorf("timeout error should mention last scanned tag, got: %v", err)
	}
}

func TestContainerTriggerErrorPropagates(t *testing.T) {
	boom := errors.New("trigger failed")
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "1.2.2"
			return []publicapi.Container{c}, nil
		},
		triggerContainer: func(ctx context.Context, id int) error { return boom },
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref:         mustRef(t, "registry.example.com/team/application", "1.2.3"),
		Wait:        true,
		TriggerScan: true,
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want trigger error", err)
	}
}

func TestContainerPollErrorPropagates(t *testing.T) {
	apiErr := &publicapi.APIError{StatusCode: 500, Method: "GET", Path: "/x"}
	api := &fakeAPI{
		listContainers: func(ctx context.Context, name string) ([]publicapi.Container, error) {
			c := scannedContainer
			c.LastScannedTag = "1.2.2"
			return []publicapi.Container{c}, nil
		},
		getContainer: func(ctx context.Context, id int) (publicapi.Container, error) {
			return publicapi.Container{}, apiErr
		},
	}
	_, err := containerService(api).Run(t.Context(), ContainerParams{
		Ref:  mustRef(t, "registry.example.com/team/application", "1.2.3"),
		Wait: true,
	})
	var got *publicapi.APIError
	if !errors.As(err, &got) {
		t.Fatalf("got %v, want APIError", err)
	}
}
