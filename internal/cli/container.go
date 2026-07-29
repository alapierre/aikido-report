package cli

import (
	"context"

	"github.com/alapierre/aikido-report/internal/gate"
	"github.com/alapierre/aikido-report/internal/imageref"
)

// ContainerCmd implements the container deployment gate.
type ContainerCmd struct {
	Globals

	Image string `help:"Container image reference, e.g. registry.example.com/team/app (may include the tag)." env:"AIKIDO_IMAGE" required:""`
	Tag   string `help:"Image tag to require a scan for; may instead be part of --image." env:"AIKIDO_TAG"`
}

// Validate is called by kong after parsing.
func (c *ContainerCmd) Validate() error {
	if err := c.validate(); err != nil {
		return err
	}
	// Parse eagerly so reference problems surface as configuration errors
	// before any network traffic.
	_, err := imageref.Parse(c.Image, c.Tag)
	return err
}

// Run executes the container deployment gate.
func (c *ContainerCmd) Run(ctx context.Context, rt *Runtime) error {
	logger := c.newLogger(rt)
	c.logConfig(logger)

	ref, err := imageref.Parse(c.Image, c.Tag)
	if err != nil {
		return err
	}
	client, err := c.newClient(rt, logger)
	if err != nil {
		return err
	}

	opCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	logger.Info("checking Aikido container scan", "image", ref.String(), "registry", ref.Registry)
	svc := &gate.ContainerService{API: client, Logger: logger}
	rep, err := svc.Run(opCtx, gate.ContainerParams{
		Ref:              ref,
		Wait:             c.Wait,
		TriggerScan:      c.TriggerScan,
		DryRun:           c.DryRun,
		PollInterval:     c.PollInterval,
		DashboardBaseURL: c.BaseURL,
	})
	if err != nil {
		return err
	}
	return c.finish(rt, logger, rep)
}
