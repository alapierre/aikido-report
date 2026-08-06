package gate

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
	"github.com/alapierre/aikido-report/internal/report"
)

// RepositoryAPI is the slice of the Aikido public API the repository gate
// needs; satisfied by *publicapi.Client.
type RepositoryAPI interface {
	ListCodeRepos(ctx context.Context, nameFilter string) ([]publicapi.CodeRepo, error)
	GetCodeRepo(ctx context.Context, id int) (publicapi.CodeRepo, error)
	TriggerCodeRepoScan(ctx context.Context, id int, types publicapi.ScanTypes) error
	ExportOpenIssues(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error)
}

// RepositoryParams configures one repository release gate run.
type RepositoryParams struct {
	// Name is the repository name as configured in Aikido.
	Name string
	// Branch, when set, is verified against the branch Aikido is
	// configured to scan; a mismatch is an error because the findings
	// would describe a different branch than the caller expects.
	Branch string
	// Commit is recorded in the report as metadata only. The Aikido public
	// API has no per-commit scans, so it cannot be verified.
	Commit string
	// Wait keeps polling until a scan result is available (and, after a
	// trigger, until a newer result than the pre-trigger one appears).
	Wait bool
	// TriggerScan requests one repository scan. Never fired in dry-run.
	TriggerScan bool
	// DryRun disables all mutating calls.
	DryRun bool
	// ScanTypes selects the optional scanners for a triggered scan.
	ScanTypes    publicapi.ScanTypes
	PollInterval time.Duration
	// DashboardBaseURL builds links into the Aikido UI.
	DashboardBaseURL string
	// IncludeCrossTargetFindings keeps findings whose Aikido attack surface
	// is docker_container instead of dropping them (see
	// dropContainerAttackSurface). Off by default.
	IncludeCrossTargetFindings bool
}

// RepositoryService runs the repository release gate.
type RepositoryService struct {
	API    RepositoryAPI
	Logger *slog.Logger
	Sleep  SleepFunc
}

// Run resolves the code repository, ensures a scan result exists (fresh
// when a scan was triggered), and returns the report with all open
// findings including source locations where available.
func (s *RepositoryService) Run(ctx context.Context, p RepositoryParams) (report.Report, error) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	sleep := s.Sleep
	if sleep == nil {
		sleep = defaultSleep
	}

	match, err := s.resolveRepository(ctx, p.Name)
	if err != nil {
		return report.Report{}, err
	}
	logger.Info("matched Aikido code repository",
		"id", match.ID, "name", match.Name, "provider", match.Provider, "scanned_branch", match.Branch)

	if p.Branch != "" && match.Branch != "" && p.Branch != match.Branch {
		return report.Report{}, fmt.Errorf(
			"%w: Aikido scans branch %q of repository %q but branch %q was requested; findings would not describe the requested branch",
			ErrBranchMismatch, match.Branch, match.Name, p.Branch)
	}

	match, err = s.ensureScanned(ctx, logger, sleep, p, match)
	if err != nil {
		return report.Report{}, err
	}

	issues, err := s.API.ExportOpenIssues(ctx, publicapi.IssueFilter{CodeRepoID: match.ID})
	if err != nil {
		return report.Report{}, err
	}
	logger.Info("fetched open findings", "count", len(issues))

	findings := findingsFromIssues(issues, p.DashboardBaseURL)
	findings = dropContainerAttackSurface(logger, findings, p.IncludeCrossTargetFindings)

	branch := p.Branch
	if branch == "" {
		branch = match.Branch
	}
	return report.Report{
		Target: report.Target{
			Kind:       report.TargetRepository,
			Name:       match.Name,
			Repository: match.Name,
			Branch:     branch,
			Commit:     p.Commit,
			ReportURL:  match.URL,
		},
		Findings: findings,
	}, nil
}

// resolveRepository finds exactly one Aikido code repository by exact name.
func (s *RepositoryService) resolveRepository(ctx context.Context, name string) (publicapi.CodeRepo, error) {
	if name == "" {
		return publicapi.CodeRepo{}, fmt.Errorf("%w: repository name is empty", ErrNoRepository)
	}
	candidates, err := s.API.ListCodeRepos(ctx, name)
	if err != nil {
		return publicapi.CodeRepo{}, err
	}

	var matches []publicapi.CodeRepo
	for _, r := range candidates {
		if r.Name == name {
			matches = append(matches, r)
		}
	}

	switch len(matches) {
	case 0:
		if len(candidates) > 0 {
			return publicapi.CodeRepo{}, fmt.Errorf("%w named %q; similarly named repositories: %s",
				ErrNoRepository, name, describeRepos(candidates))
		}
		return publicapi.CodeRepo{}, fmt.Errorf("%w named %q", ErrNoRepository, name)
	case 1:
		return matches[0], nil
	default:
		return publicapi.CodeRepo{}, fmt.Errorf("%w: %d Aikido code repositories are named %q (%s)",
			ErrAmbiguousMatch, len(matches), name, describeRepos(matches))
	}
}

func describeRepos(repos []publicapi.CodeRepo) string {
	out := make([]string, 0, len(repos))
	for _, r := range repos {
		desc := fmt.Sprintf("%s id=%d provider=%s", r.Name, r.ID, r.Provider)
		if r.URL != "" {
			desc += " url=" + r.URL
		}
		out = append(out, desc)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// ensureScanned makes sure findings will describe a real scan: without a
// trigger any existing result is accepted; after a trigger the service
// waits for a result newer than the pre-trigger one.
func (s *RepositoryService) ensureScanned(ctx context.Context, logger *slog.Logger, sleep SleepFunc, p RepositoryParams, match publicapi.CodeRepo) (publicapi.CodeRepo, error) {
	baseline := match.LastScannedAt

	triggered := false
	if p.TriggerScan && !p.DryRun {
		if !match.Active {
			return publicapi.CodeRepo{}, fmt.Errorf("%w: cannot trigger a scan of code repository %q (id %d)", ErrInactiveRepository, match.Name, match.ID)
		}
		logger.Info("triggering Aikido repository scan",
			"id", match.ID, "sast", p.ScanTypes.SAST, "iac", p.ScanTypes.IaC, "secrets", p.ScanTypes.Secrets)
		if err := s.API.TriggerCodeRepoScan(ctx, match.ID, p.ScanTypes); err != nil {
			return publicapi.CodeRepo{}, err
		}
		triggered = true
	} else if p.DryRun && p.TriggerScan {
		logger.Info("dry-run: skipping scan trigger", "id", match.ID)
	}

	scanReady := func(r publicapi.CodeRepo) bool {
		if triggered {
			return r.LastScannedAt > baseline
		}
		return r.LastScannedAt > 0
	}

	if scanReady(match) {
		return match, nil
	}
	if !p.Wait {
		if triggered {
			logger.Warn("scan triggered but --wait is disabled; findings reflect the previous scan")
			return match, nil
		}
		return publicapi.CodeRepo{}, fmt.Errorf("%w: repository %q has never been scanned by Aikido; enable --trigger-scan and --wait",
			ErrScanNotReady, match.Name)
	}

	current := match
	err := pollUntil(ctx, sleep, p.PollInterval, func(ctx context.Context) (bool, error) {
		r, err := s.API.GetCodeRepo(ctx, match.ID)
		if err != nil {
			return false, err
		}
		current = r
		if scanReady(r) {
			return true, nil
		}
		logger.Info("scan result not ready yet", "repository", match.Name, "next_poll_in", p.PollInterval)
		return false, nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return publicapi.CodeRepo{}, fmt.Errorf("%w: repository %q: %w", ErrScanTimeout, match.Name, ctx.Err())
		}
		return publicapi.CodeRepo{}, err
	}
	return current, nil
}
