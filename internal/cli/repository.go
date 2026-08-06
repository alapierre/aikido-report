package cli

import (
	"context"
	"fmt"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
	"github.com/alapierre/aikido-report/internal/gate"
)

// RepositoryCmd implements the repository release gate. The Aikido public
// API scans the branch configured in Aikido; --branch is verified against
// that configuration and --commit is recorded in the report as metadata.
type RepositoryCmd struct {
	Globals

	Repository                 string   `help:"Aikido code repository name (defaults to BITBUCKET_REPO_SLUG in Bitbucket Pipelines)." env:"AIKIDO_REPOSITORY,BITBUCKET_REPO_SLUG" required:""`
	Branch                     string   `help:"Expected branch; verified against the branch Aikido scans (defaults to BITBUCKET_BRANCH)." env:"AIKIDO_BRANCH,BITBUCKET_BRANCH"`
	Commit                     string   `help:"Commit recorded in the report metadata (defaults to BITBUCKET_COMMIT)." env:"AIKIDO_COMMIT,BITBUCKET_COMMIT"`
	ScanTypes                  []string `help:"Extra scanners for a triggered scan: sast, iac, secrets (dependency scan always runs)." name:"scan-types" env:"AIKIDO_SCAN_TYPES" placeholder:"TYPE,..."`
	IncludeCrossTargetFindings bool     `help:"Keep findings whose Aikido attack surface is docker_container. These describe the linked container image, which in a build-then-scan-repo-then-build-image pipeline may not even exist yet for the current commit. Off by default." name:"include-cross-target-findings" env:"AIKIDO_INCLUDE_CROSS_TARGET_FINDINGS"`
}

// Validate is called by kong after parsing.
func (c *RepositoryCmd) Validate() error {
	if err := c.validate(); err != nil {
		return err
	}
	_, err := c.scanTypes()
	return err
}

func (c *RepositoryCmd) scanTypes() (publicapi.ScanTypes, error) {
	var types publicapi.ScanTypes
	for _, t := range c.ScanTypes {
		switch t {
		case "sast":
			types.SAST = true
		case "iac":
			types.IaC = true
		case "secrets":
			types.Secrets = true
		default:
			return publicapi.ScanTypes{}, fmt.Errorf("invalid --scan-types value %q: valid values are sast, iac, secrets", t)
		}
	}
	return types, nil
}

// Run executes the repository release gate.
func (c *RepositoryCmd) Run(ctx context.Context, rt *Runtime) error {
	logger := c.newLogger(rt)
	c.logConfig(logger)

	types, err := c.scanTypes()
	if err != nil {
		return err
	}
	client, err := c.newClient(rt, logger)
	if err != nil {
		return err
	}

	opCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	logger.Info("checking Aikido repository scan", "repository", c.Repository, "branch", c.Branch, "commit", c.Commit)
	svc := &gate.RepositoryService{API: client, Logger: logger}
	rep, err := svc.Run(opCtx, gate.RepositoryParams{
		Name:                       c.Repository,
		Branch:                     c.Branch,
		Commit:                     c.Commit,
		Wait:                       c.Wait,
		TriggerScan:                c.TriggerScan,
		DryRun:                     c.DryRun,
		ScanTypes:                  types,
		PollInterval:               c.PollInterval,
		DashboardBaseURL:           c.BaseURL,
		IncludeCrossTargetFindings: c.IncludeCrossTargetFindings,
	})
	if err != nil {
		return err
	}
	return c.finish(rt, logger, rep)
}
