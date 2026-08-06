package gate

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
	"github.com/alapierre/aikido-report/internal/report"
)

var scannedRepo = publicapi.CodeRepo{
	ID: 55, Name: "my-project", Provider: "bitbucket",
	URL: "https://bitbucket.org/acme/my-project", Branch: "master",
	LastScannedAt: 1753700000, Active: true,
}

func repositoryService(api *fakeAPI) *RepositoryService {
	return &RepositoryService{API: api, Logger: testLogger(), Sleep: instantSleep}
}

func TestRepositoryHappyPathExistingScan(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			if name != "my-project" {
				t.Errorf("filter name = %q", name)
			}
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			if filter.CodeRepoID != 55 {
				t.Errorf("filter = %+v", filter)
			}
			return []publicapi.Issue{
				{ID: 1, GroupID: 10, Type: "sast", Rule: "SQL Injection", Severity: "high",
					AffectedFile: "internal/db/query.go", StartLine: 118, EndLine: 124},
				{ID: 2, GroupID: 11, Type: "open_source", Severity: "critical", CVEID: "CVE-2025-9",
					AffectedPackage: "left-pad", InstalledVersion: "1.0.0"},
			}, nil
		},
	}
	rep, err := repositoryService(api).Run(t.Context(), RepositoryParams{
		Name:   "my-project",
		Branch: "master",
		Commit: "abc123def456",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	target := rep.Target
	if target.Kind != report.TargetRepository || target.Repository != "my-project" ||
		target.Branch != "master" || target.Commit != "abc123def456" {
		t.Errorf("unexpected target: %+v", target)
	}
	if target.ReportURL != "https://bitbucket.org/acme/my-project" {
		t.Errorf("ReportURL = %q", target.ReportURL)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(rep.Findings))
	}
	sast := rep.Findings[0]
	if sast.File != "internal/db/query.go" || sast.StartLine != 118 || sast.EndLine != 124 {
		t.Errorf("sast location lost: %+v", sast)
	}
	dep := rep.Findings[1]
	if dep.File != "" || dep.StartLine != 0 {
		t.Errorf("dependency finding should have no location: %+v", dep)
	}
}

func TestRepositoryBranchDefaultsToAikidoConfig(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
	}
	rep, err := repositoryService(api).Run(t.Context(), RepositoryParams{Name: "my-project"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Target.Branch != "master" {
		t.Errorf("Branch = %q, want Aikido-configured branch", rep.Target.Branch)
	}
}

func TestRepositoryBranchMismatch(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
	}
	_, err := repositoryService(api).Run(t.Context(), RepositoryParams{
		Name:   "my-project",
		Branch: "feature/foo",
	})
	if !errors.Is(err, ErrBranchMismatch) {
		t.Fatalf("got %v, want ErrBranchMismatch", err)
	}
	if !strings.Contains(err.Error(), "master") || !strings.Contains(err.Error(), "feature/foo") {
		t.Errorf("error should name both branches, got: %v", err)
	}
}

func TestRepositoryNotFound(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{
				{ID: 1, Name: "my-project-legacy", Provider: "github"},
			}, nil
		},
	}
	_, err := repositoryService(api).Run(t.Context(), RepositoryParams{Name: "my-project"})
	if !errors.Is(err, ErrNoRepository) {
		t.Fatalf("got %v, want ErrNoRepository", err)
	}
	if !strings.Contains(err.Error(), "my-project-legacy") {
		t.Errorf("error should list similar names, got: %v", err)
	}
}

func TestRepositoryEmptyName(t *testing.T) {
	_, err := repositoryService(&fakeAPI{}).Run(t.Context(), RepositoryParams{})
	if !errors.Is(err, ErrNoRepository) {
		t.Fatalf("got %v, want ErrNoRepository", err)
	}
}

func TestRepositoryAmbiguousName(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{
				{ID: 1, Name: "my-project", Provider: "github"},
				{ID: 2, Name: "my-project", Provider: "bitbucket"},
			}, nil
		},
	}
	_, err := repositoryService(api).Run(t.Context(), RepositoryParams{Name: "my-project"})
	if !errors.Is(err, ErrAmbiguousMatch) {
		t.Fatalf("got %v, want ErrAmbiguousMatch", err)
	}
	if !strings.Contains(err.Error(), "github") || !strings.Contains(err.Error(), "bitbucket") {
		t.Errorf("error should describe both candidates, got: %v", err)
	}
}

func TestRepositoryNeverScannedNoWait(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			r := scannedRepo
			r.LastScannedAt = -1
			return []publicapi.CodeRepo{r}, nil
		},
	}
	_, err := repositoryService(api).Run(t.Context(), RepositoryParams{Name: "my-project"})
	if !errors.Is(err, ErrScanNotReady) {
		t.Fatalf("got %v, want ErrScanNotReady", err)
	}
}

func TestRepositoryTriggerAndWaitForNewerScan(t *testing.T) {
	var triggers, polls atomic.Int32
	baseline := scannedRepo.LastScannedAt
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
		triggerCodeRepo: func(ctx context.Context, id int, types publicapi.ScanTypes) error {
			triggers.Add(1)
			if !types.SAST || !types.Secrets || types.IaC {
				t.Errorf("unexpected scan types: %+v", types)
			}
			return nil
		},
		getCodeRepo: func(ctx context.Context, id int) (publicapi.CodeRepo, error) {
			r := scannedRepo
			if polls.Add(1) >= 3 {
				r.LastScannedAt = baseline + 60
			}
			return r, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
	}
	_, err := repositoryService(api).Run(t.Context(), RepositoryParams{
		Name:        "my-project",
		Wait:        true,
		TriggerScan: true,
		ScanTypes:   publicapi.ScanTypes{SAST: true, Secrets: true},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if triggers.Load() != 1 {
		t.Errorf("scan triggered %d times, want exactly 1", triggers.Load())
	}
	if polls.Load() != 3 {
		t.Errorf("polled %d times, want 3 (existing scan must not satisfy the wait)", polls.Load())
	}
}

func TestRepositoryTriggerWithoutWaitUsesPreviousScan(t *testing.T) {
	var triggers atomic.Int32
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
		triggerCodeRepo: func(ctx context.Context, id int, types publicapi.ScanTypes) error {
			triggers.Add(1)
			return nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
	}
	if _, err := repositoryService(api).Run(t.Context(), RepositoryParams{
		Name:        "my-project",
		TriggerScan: true,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if triggers.Load() != 1 {
		t.Errorf("triggers = %d, want 1", triggers.Load())
	}
}

func TestRepositoryDryRunNeverTriggers(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return nil, nil
		},
		// triggerCodeRepo nil: any trigger call fails the run.
	}
	if _, err := repositoryService(api).Run(t.Context(), RepositoryParams{
		Name:        "my-project",
		TriggerScan: true,
		DryRun:      true,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRepositoryInactiveCannotTrigger(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			r := scannedRepo
			r.Active = false
			return []publicapi.CodeRepo{r}, nil
		},
	}
	_, err := repositoryService(api).Run(t.Context(), RepositoryParams{
		Name:        "my-project",
		TriggerScan: true,
	})
	if !errors.Is(err, ErrInactiveRepository) {
		t.Fatalf("got %v, want ErrInactiveRepository", err)
	}
}

func TestRepositoryPollTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			r := scannedRepo
			r.LastScannedAt = -1
			return []publicapi.CodeRepo{r}, nil
		},
		getCodeRepo: func(ctx context.Context, id int) (publicapi.CodeRepo, error) {
			r := scannedRepo
			r.LastScannedAt = -1
			return r, nil
		},
	}
	svc := &RepositoryService{API: api, Logger: testLogger(), Sleep: sleepCancellingAfter(2, cancel)}
	_, err := svc.Run(ctx, RepositoryParams{Name: "my-project", Wait: true})
	if !errors.Is(err, ErrScanTimeout) {
		t.Fatalf("got %v, want ErrScanTimeout", err)
	}
}

func TestRepositoryCategoriesMapped(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return []publicapi.Issue{
				{ID: 1, GroupID: 1, Type: "sast", Severity: "high"},
				{ID: 2, GroupID: 2, Type: "iac", Severity: "low"},
				{ID: 3, GroupID: 3, Type: "leaked_secret", Severity: "critical"},
				{ID: 4, GroupID: 4, Type: "ai_pentest", Severity: "weird"},
			}, nil
		},
	}
	rep, err := repositoryService(api).Run(t.Context(), RepositoryParams{Name: "my-project"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []report.Category{report.CategorySAST, report.CategoryIaC, report.CategorySecret, report.CategoryUnknown}
	for i, f := range rep.Findings {
		if f.Category != want[i] {
			t.Errorf("finding %d category = %q, want %q", i, f.Category, want[i])
		}
	}
	unknown := rep.Findings[3]
	if unknown.Severity != report.SeverityUnknown {
		t.Errorf("unknown severity = %q", unknown.Severity)
	}
	if unknown.Properties["aikido_type"] != "ai_pentest" {
		t.Errorf("original type not preserved: %+v", unknown.Properties)
	}
}

// TestRepositoryDropsContainerAttackSurface mirrors a real regression: the
// issues/export for a code repository also returns issues that belong to
// its linked container image (attack_surface "docker_container"). In a
// pipeline that scans the repository before the image is built, those
// findings describe an unrelated artifact and must not appear in the
// repository report by default.
func TestRepositoryDropsContainerAttackSurface(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return []publicapi.Issue{
				{ID: 1, GroupID: 1, Type: "open_source", Severity: "low",
					AttackSurface: "backend", AffectedFile: "pom.xml", AffectedPackage: "micrometer-core"},
				{ID: 2, GroupID: 1, Type: "open_source", Severity: "high",
					AttackSurface: "docker_container", AffectedFile: "app/libs/micrometer-core-1.15.4.jar", AffectedPackage: "micrometer-core"},
			}, nil
		},
	}
	rep, err := repositoryService(api).Run(t.Context(), RepositoryParams{Name: "my-project"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].File != "pom.xml" {
		t.Fatalf("got %+v, want only the pom.xml finding", rep.Findings)
	}
}

func TestRepositoryIncludeCrossTargetFindings(t *testing.T) {
	api := &fakeAPI{
		listCodeRepos: func(ctx context.Context, name string) ([]publicapi.CodeRepo, error) {
			return []publicapi.CodeRepo{scannedRepo}, nil
		},
		exportIssues: func(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error) {
			return []publicapi.Issue{
				{ID: 1, GroupID: 1, Type: "open_source", Severity: "low", AttackSurface: "backend"},
				{ID: 2, GroupID: 1, Type: "open_source", Severity: "high", AttackSurface: "docker_container"},
			}, nil
		},
	}
	rep, err := repositoryService(api).Run(t.Context(), RepositoryParams{
		Name:                       "my-project",
		IncludeCrossTargetFindings: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (filtering disabled)", len(rep.Findings))
	}
}
