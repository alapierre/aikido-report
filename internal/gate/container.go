package gate

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
	"github.com/alapierre/aikido-report/internal/imageref"
	"github.com/alapierre/aikido-report/internal/report"
)

// ContainerAPI is the slice of the Aikido public API the container gate
// needs. It is defined here, on the consumer side, and satisfied by
// *publicapi.Client.
type ContainerAPI interface {
	ListContainers(ctx context.Context, nameFilter string) ([]publicapi.Container, error)
	GetContainer(ctx context.Context, id int) (publicapi.Container, error)
	TriggerContainerScan(ctx context.Context, id int) error
	ExportOpenIssues(ctx context.Context, filter publicapi.IssueFilter) ([]publicapi.Issue, error)
}

// ContainerParams configures one container gate run.
type ContainerParams struct {
	Ref imageref.Ref
	// Wait keeps polling until the expected tag is scanned or the context
	// (operation timeout) ends.
	Wait bool
	// TriggerScan requests one ad-hoc scan when the expected tag has no
	// result yet. The trigger happens at most once and never in dry-run.
	TriggerScan bool
	// DryRun disables all mutating calls (the scan trigger).
	DryRun       bool
	PollInterval time.Duration
	// DashboardBaseURL builds links into the Aikido UI.
	DashboardBaseURL string
}

// ContainerService runs the container deployment gate.
type ContainerService struct {
	API    ContainerAPI
	Logger *slog.Logger
	Sleep  SleepFunc
}

// Run resolves the container repository, ensures the expected tag has a
// scan result, and returns the report with all open findings.
func (s *ContainerService) Run(ctx context.Context, p ContainerParams) (report.Report, error) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	sleep := s.Sleep
	if sleep == nil {
		sleep = defaultSleep
	}

	match, err := s.resolveContainer(ctx, p.Ref)
	if err != nil {
		return report.Report{}, err
	}
	logger.Info("matched Aikido container repository",
		"id", match.ID, "name", match.Name, "registry", match.RegistryName)

	match, err = s.ensureTagScanned(ctx, logger, sleep, p, match)
	if err != nil {
		return report.Report{}, err
	}

	issues, err := s.API.ExportOpenIssues(ctx, publicapi.IssueFilter{ContainerRepoID: match.ID})
	if err != nil {
		return report.Report{}, err
	}
	logger.Info("fetched open findings", "count", len(issues))

	return report.Report{
		Target: report.Target{
			Kind:      report.TargetContainer,
			Name:      match.Name,
			Registry:  match.RegistryName,
			Image:     p.Ref.Path,
			Tag:       p.Ref.Tag,
			ReportURL: fmt.Sprintf("%s/container/%d", strings.TrimRight(p.DashboardBaseURL, "/"), match.ID),
		},
		Findings: findingsFromIssues(issues, p.DashboardBaseURL),
	}, nil
}

// resolveContainer finds exactly one Aikido container repository for the
// reference. Zero or multiple matches are hard errors: the gate must never
// silently check a different image than the one being deployed.
func (s *ContainerService) resolveContainer(ctx context.Context, ref imageref.Ref) (publicapi.Container, error) {
	candidates, err := s.API.ListContainers(ctx, ref.ShortName)
	if err != nil {
		return publicapi.Container{}, err
	}

	var matches []publicapi.Container
	for _, c := range candidates {
		if !containerNameMatches(c.Name, ref) {
			continue
		}
		if ref.Registry != "" && !strings.EqualFold(c.RegistryName, ref.Registry) {
			continue
		}
		matches = append(matches, c)
	}

	switch len(matches) {
	case 0:
		if len(candidates) > 0 {
			return publicapi.Container{}, fmt.Errorf("%w for image %q; similarly named repositories exist in: %s",
				ErrNoRepository, ref.String(), describeRegistries(candidates))
		}
		return publicapi.Container{}, fmt.Errorf("%w for image %q", ErrNoRepository, ref.String())
	case 1:
		m := matches[0]
		if m.IsEmpty {
			return publicapi.Container{}, fmt.Errorf("%w: Aikido container repository %q (id %d) has no image pushed", ErrEmptyRepository, m.Name, m.ID)
		}
		return m, nil
	default:
		return publicapi.Container{}, fmt.Errorf("%w: image %q matches %d Aikido container repositories (%s); qualify the registry in --image",
			ErrAmbiguousMatch, ref.String(), len(matches), describeRegistries(matches))
	}
}

// containerNameMatches accepts either the full repository path or its last
// segment, because Aikido may store the name with or without a namespace
// depending on the registry integration.
func containerNameMatches(aikidoName string, ref imageref.Ref) bool {
	return aikidoName == ref.Path || aikidoName == ref.ShortName
}

func describeRegistries(containers []publicapi.Container) string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range containers {
		reg := c.RegistryName
		if reg == "" {
			reg = "(no registry)"
		}
		if !seen[reg] {
			seen[reg] = true
			out = append(out, fmt.Sprintf("%s id=%d", reg, c.ID))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// ensureTagScanned returns once Aikido has a scan result for the expected
// tag, triggering at most one ad-hoc scan and polling within the caller's
// context deadline.
//
// Matching last_scanned_tag alone is not enough: Aikido appears to flip
// last_scanned_tag to the new tag before the underlying issue data for
// that scan is actually settled, so a poll can race a scan still in
// flight and export stale findings from the previous scan. After a
// trigger, last_scanned_at must also be strictly newer than the
// pre-trigger baseline — the same safeguard RepositoryService.ensureScanned
// already applies.
func (s *ContainerService) ensureTagScanned(ctx context.Context, logger *slog.Logger, sleep SleepFunc, p ContainerParams, match publicapi.Container) (publicapi.Container, error) {
	baseline := match.LastScannedAt
	triggered := false

	tagReady := func(c publicapi.Container) bool {
		if !tagScanned(c, p.Ref.Tag) {
			return false
		}
		if triggered {
			return c.LastScannedAt > baseline
		}
		return true
	}

	if tagReady(match) {
		logger.Info("expected tag already scanned", "tag", p.Ref.Tag)
		return match, nil
	}

	if p.TriggerScan && !p.DryRun {
		if !match.IsActive {
			return publicapi.Container{}, fmt.Errorf("%w: cannot trigger a scan of container repository %q (id %d)", ErrInactiveRepository, match.Name, match.ID)
		}
		// The public API scan trigger accepts no tag: Aikido scans whatever
		// the repository's tag filter selects. The trigger is fired exactly
		// once; polling below only observes.
		logger.Info("triggering Aikido container scan", "id", match.ID, "tag_filter", match.TagFilter)
		if err := s.API.TriggerContainerScan(ctx, match.ID); err != nil {
			return publicapi.Container{}, err
		}
		triggered = true
	} else if p.DryRun && p.TriggerScan {
		logger.Info("dry-run: skipping scan trigger", "id", match.ID)
	}

	if !p.Wait {
		return publicapi.Container{}, fmt.Errorf("%w: tag %q of %q is not scanned (last scanned tag: %s); enable --wait or run again later",
			ErrScanNotReady, p.Ref.Tag, p.Ref.String(), lastTagInfo(match))
	}

	current := match
	err := pollUntil(ctx, sleep, p.PollInterval, func(ctx context.Context) (bool, error) {
		c, err := s.API.GetContainer(ctx, match.ID)
		if err != nil {
			return false, err
		}
		current = c
		if tagReady(c) {
			return true, nil
		}
		logger.Info("scan result not ready yet",
			"tag", p.Ref.Tag, "last_scanned_tag", c.LastScannedTag, "next_poll_in", p.PollInterval)
		return false, nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return publicapi.Container{}, fmt.Errorf("%w: tag %q of %q (last scanned tag: %s): %w",
				ErrScanTimeout, p.Ref.Tag, p.Ref.String(), lastTagInfo(current), ctx.Err())
		}
		return publicapi.Container{}, err
	}
	return current, nil
}

// tagScanned reports whether the container's latest scan covered the
// expected tag. Tags compare case-sensitively, per the OCI spec.
func tagScanned(c publicapi.Container, tag string) bool {
	return c.LastScannedTag == tag && c.LastScannedAt > 0
}

func lastTagInfo(c publicapi.Container) string {
	if c.LastScannedTag == "" {
		return "none"
	}
	return fmt.Sprintf("%q", c.LastScannedTag)
}
