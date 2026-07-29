// Package cli wires the command line interface: flag and environment
// parsing (kong), logger construction, signal handling, exit codes, and
// the Bitbucket-pipe entry mode. It contains no Aikido API logic and no
// SARIF construction.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
)

const description = `Generate SARIF 2.1.0 reports from Aikido Security scan results.

aikido-report is an unofficial tool, not affiliated with Aikido Security.
It resolves a container image or code repository in Aikido, optionally
triggers a scan, waits for the result, exports the open findings as SARIF,
and can act as a CI quality gate.`

// CLI is the kong root.
type CLI struct {
	Container  ContainerCmd  `cmd:"" help:"Check a container image scan and write a SARIF report (container deployment gate)."`
	Repository RepositoryCmd `cmd:"" help:"Check a code repository scan and write a SARIF report (repository release gate)."`

	Version kong.VersionFlag `help:"Print version and exit."`
}

// Runtime carries process-level dependencies into command Run methods.
type Runtime struct {
	Version string
	Stdout  io.Writer
	Stderr  io.Writer
}

// kongExit is panicked by the kong exit hook (e.g. --help, --version) and
// recovered in Main so tests never os.Exit.
type kongExit struct{ code int }

// Main parses arguments and runs the selected command, returning the
// process exit code: 0 success, 1 technical/configuration error, or the
// configured quality-gate code.
func Main(args []string, version string, stdout, stderr io.Writer) (exitCode int) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(kongExit)
			if !ok {
				panic(r)
			}
			exitCode = e.code
		}
	}()

	parser, err := kong.New(&CLI{},
		kong.Name("aikido-report"),
		kong.Description(description),
		kong.UsageOnError(),
		kong.Writers(stdout, stderr),
		kong.Vars{"version": version},
		kong.Exit(func(code int) { panic(kongExit{code}) }),
	)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "aikido-report: internal error:", err)
		return 1
	}

	// Bitbucket pipes start the container with no argv and configure it
	// via environment variables only; synthesize the subcommand.
	if len(args) == 0 {
		pipeArgs, err := PipeModeArgs(os.Getenv)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "aikido-report: error:", err)
			return 1
		}
		args = pipeArgs
	}

	kctx, err := parser.Parse(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "aikido-report: error:", err)
		_, _ = fmt.Fprintln(stderr, "Run 'aikido-report --help' for usage.")
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rt := &Runtime{Version: version, Stdout: stdout, Stderr: stderr}
	kctx.BindTo(ctx, (*context.Context)(nil))
	kctx.Bind(rt)

	if err := kctx.Run(); err != nil {
		var gateErr *ExitCodeError
		if errors.As(err, &gateErr) {
			_, _ = fmt.Fprintln(stderr, "aikido-report:", gateErr.Message)
			return gateErr.Code
		}
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			_, _ = fmt.Fprintln(stderr, "aikido-report: canceled by signal")
			return 1
		}
		_, _ = fmt.Fprintln(stderr, "aikido-report: error:", err)
		return 1
	}
	return 0
}
