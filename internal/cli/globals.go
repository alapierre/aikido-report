package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
	"github.com/alapierre/aikido-report/internal/report"
	"github.com/alapierre/aikido-report/internal/sarifgen"
)

// Globals holds the flags shared by both commands. Every flag has an
// AIKIDO_* environment fallback so the tool can run as a Bitbucket pipe,
// where only environment variables are available. Flags always take
// precedence over environment variables.
type Globals struct {
	Output       string        `help:"Where to write the SARIF report; '-' writes to stdout (logs then go to stderr only)." short:"o" required:"" env:"AIKIDO_OUTPUT" placeholder:"FILE"`
	BaseURL      string        `help:"Aikido application base URL (use the regional host if applicable)." name:"base-url" env:"AIKIDO_BASE_URL" default:"https://app.aikido.dev"`
	ClientID     string        `help:"Aikido OAuth client ID (workspace Integrations settings)." name:"client-id" env:"AIKIDO_CLIENT_ID" required:""`
	ClientSecret string        `help:"Aikido OAuth client secret." name:"client-secret" env:"AIKIDO_CLIENT_SECRET" required:""`
	FailSeverity string        `help:"Enable the quality gate: exit non-zero when an open finding at or above this severity exists (critical|high|medium|low). Empty disables the gate; the report is always written first." name:"fail-severity" env:"AIKIDO_FAIL_SEVERITY" placeholder:"SEVERITY"`
	ExitCode     int           `help:"Exit code used when the quality gate fails (2-255; 1 is reserved for technical errors)." name:"exit-code" env:"AIKIDO_EXIT_CODE" default:"2"`
	Wait         bool          `help:"Wait (poll) until the expected scan result is available. Disable with --no-wait." negatable:"" env:"AIKIDO_WAIT" default:"true"`
	TriggerScan  bool          `help:"Trigger one Aikido scan when the expected result is missing." name:"trigger-scan" env:"AIKIDO_TRIGGER_SCAN"`
	PollInterval time.Duration `help:"Delay between poll requests." name:"poll-interval" env:"AIKIDO_POLL_INTERVAL" default:"15s"`
	Timeout      time.Duration `help:"Overall time budget for the whole operation." env:"AIKIDO_TIMEOUT" default:"10m"`
	HTTPTimeout  time.Duration `help:"Timeout for a single HTTP request." name:"http-timeout" env:"AIKIDO_HTTP_TIMEOUT" default:"30s"`
	DryRun       bool          `help:"Read-only mode: never trigger scans, still fetch findings and write the report." name:"dry-run" env:"AIKIDO_DRY_RUN"`
	Verbose      bool          `help:"Verbose (debug) logging on stderr. Never logs credentials." short:"v" env:"AIKIDO_VERBOSE"`
}

// validate enforces the flag rules kong tags cannot express.
func (g *Globals) validate() error {
	if g.FailSeverity != "" {
		switch report.ParseSeverity(g.FailSeverity) {
		case report.SeverityCritical, report.SeverityHigh, report.SeverityMedium, report.SeverityLow:
		default:
			return fmt.Errorf("invalid --fail-severity %q: use critical, high, medium or low", g.FailSeverity)
		}
		if g.ExitCode == 1 {
			return errors.New("--exit-code 1 is reserved for technical errors; use another code (default 2)")
		}
		if g.ExitCode < 2 || g.ExitCode > 255 {
			return fmt.Errorf("invalid --exit-code %d: use a value between 2 and 255", g.ExitCode)
		}
	}
	if g.PollInterval <= 0 {
		return errors.New("--poll-interval must be positive")
	}
	if g.Timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	return nil
}

// failSeverity returns the parsed gate threshold, or empty when disabled.
func (g *Globals) failSeverity() report.Severity {
	if g.FailSeverity == "" {
		return ""
	}
	return report.ParseSeverity(g.FailSeverity)
}

// newLogger builds the stderr logger. Operational output never goes to
// stdout, which must stay clean for --output=-.
func (g *Globals) newLogger(rt *Runtime) *slog.Logger {
	level := slog.LevelInfo
	if g.Verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(rt.Stderr, &slog.HandlerOptions{Level: level}))
}

// newClient builds the Aikido public API client shared by both commands.
func (g *Globals) newClient(rt *Runtime, logger *slog.Logger) (*publicapi.Client, error) {
	return publicapi.New(publicapi.Config{
		BaseURL:      g.BaseURL,
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		HTTPTimeout:  g.HTTPTimeout,
		UserAgent:    "aikido-report/" + rt.Version,
		Logger:       logger,
	})
}

// logConfig records the effective non-secret configuration. Credentials
// are deliberately absent.
func (g *Globals) logConfig(logger *slog.Logger) {
	logger.Debug("configuration",
		"base_url", g.BaseURL,
		"output", g.Output,
		"wait", g.Wait,
		"trigger_scan", g.TriggerScan,
		"dry_run", g.DryRun,
		"poll_interval", g.PollInterval,
		"timeout", g.Timeout,
		"http_timeout", g.HTTPTimeout,
		"fail_severity", g.FailSeverity,
		"exit_code", g.ExitCode,
	)
}

// finish writes the SARIF report and only afterwards evaluates the quality
// gate, so a failed gate never suppresses the report.
func (g *Globals) finish(rt *Runtime, logger *slog.Logger, rep report.Report) error {
	gen := &sarifgen.Generator{ToolVersion: rt.Version}
	if g.Output == "-" {
		if err := gen.Write(rep, rt.Stdout); err != nil {
			return err
		}
	} else {
		if err := gen.WriteFile(rep, g.Output); err != nil {
			return err
		}
		logger.Info("SARIF report written", "path", g.Output)
	}
	logSummary(logger, rep)
	return evaluateGate(rep, g.failSeverity(), g.ExitCode)
}

func logSummary(logger *slog.Logger, rep report.Report) {
	counts := map[report.Severity]int{}
	for _, f := range rep.Findings {
		counts[f.Severity]++
	}
	logger.Info("findings summary",
		"total", len(rep.Findings),
		"critical", counts[report.SeverityCritical],
		"high", counts[report.SeverityHigh],
		"medium", counts[report.SeverityMedium],
		"low", counts[report.SeverityLow],
		"info", counts[report.SeverityInfo],
		"unknown", counts[report.SeverityUnknown],
	)
}
