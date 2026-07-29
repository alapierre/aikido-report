package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

// parseCLI runs kong parsing exactly like Main but without executing the
// command, so configuration resolution is testable in isolation.
func parseCLI(t *testing.T, args ...string) (*CLI, error) {
	t.Helper()
	root := &CLI{}
	parser, err := kong.New(root,
		kong.Name("aikido-report"),
		kong.Vars{"version": "test"},
		kong.Exit(func(code int) { t.Fatalf("kong exited with %d", code) }),
	)
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	_, err = parser.Parse(args)
	return root, err
}

var minimalContainerArgs = []string{
	"container",
	"--image", "registry.example.com/team/app",
	"--tag", "1.0",
	"--output", "out.sarif",
	"--client-id", "id",
	"--client-secret", "secret",
}

func TestContainerDefaults(t *testing.T) {
	root, err := parseCLI(t, minimalContainerArgs...)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	g := root.Container.Globals
	if g.BaseURL != "https://app.aikido.dev" {
		t.Errorf("BaseURL = %q", g.BaseURL)
	}
	if !g.Wait || g.TriggerScan || g.DryRun || g.Verbose {
		t.Errorf("unexpected bool defaults: %+v", g)
	}
	if g.PollInterval != 15*time.Second || g.Timeout != 10*time.Minute || g.HTTPTimeout != 30*time.Second {
		t.Errorf("unexpected duration defaults: %+v", g)
	}
	if g.FailSeverity != "" || g.ExitCode != 2 {
		t.Errorf("unexpected gate defaults: fail=%q exit=%d", g.FailSeverity, g.ExitCode)
	}
}

func TestEnvironmentFallbacks(t *testing.T) {
	t.Setenv("AIKIDO_IMAGE", "ghcr.io/org/app")
	t.Setenv("AIKIDO_TAG", "2.0")
	t.Setenv("AIKIDO_OUTPUT", "env.sarif")
	t.Setenv("AIKIDO_CLIENT_ID", "env-id")
	t.Setenv("AIKIDO_CLIENT_SECRET", "env-secret")
	t.Setenv("AIKIDO_FAIL_SEVERITY", "high")
	t.Setenv("AIKIDO_EXIT_CODE", "3")
	t.Setenv("AIKIDO_WAIT", "false")
	t.Setenv("AIKIDO_TRIGGER_SCAN", "true")
	t.Setenv("AIKIDO_POLL_INTERVAL", "5s")
	t.Setenv("AIKIDO_VERBOSE", "true")

	root, err := parseCLI(t, "container")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c := root.Container
	if c.Image != "ghcr.io/org/app" || c.Tag != "2.0" || c.Output != "env.sarif" ||
		c.ClientID != "env-id" || c.ClientSecret != "env-secret" {
		t.Errorf("env values not picked up: %+v", c)
	}
	if c.FailSeverity != "high" || c.ExitCode != 3 || c.Wait || !c.TriggerScan ||
		c.PollInterval != 5*time.Second || !c.Verbose {
		t.Errorf("env values not picked up: %+v", c.Globals)
	}
}

func TestFlagsTakePrecedenceOverEnv(t *testing.T) {
	t.Setenv("AIKIDO_IMAGE", "from-env/app")
	t.Setenv("AIKIDO_TAG", "env-tag")
	root, err := parseCLI(t, minimalContainerArgs...)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if root.Container.Image != "registry.example.com/team/app" || root.Container.Tag != "1.0" {
		t.Errorf("flags did not win over env: %+v", root.Container)
	}
}

func TestBitbucketFallbacksForRepository(t *testing.T) {
	t.Setenv("BITBUCKET_REPO_SLUG", "my-project")
	t.Setenv("BITBUCKET_BRANCH", "master")
	t.Setenv("BITBUCKET_COMMIT", "abc123")
	root, err := parseCLI(t,
		"repository", "--output", "o.sarif", "--client-id", "i", "--client-secret", "s")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c := root.Repository
	if c.Repository != "my-project" || c.Branch != "master" || c.Commit != "abc123" {
		t.Errorf("Bitbucket fallbacks not applied: %+v", c)
	}
}

func TestAikidoEnvWinsOverBitbucketEnv(t *testing.T) {
	t.Setenv("AIKIDO_REPOSITORY", "aikido-name")
	t.Setenv("BITBUCKET_REPO_SLUG", "slug-name")
	root, err := parseCLI(t,
		"repository", "--output", "o.sarif", "--client-id", "i", "--client-secret", "s")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if root.Repository.Repository != "aikido-name" {
		t.Errorf("Repository = %q, want AIKIDO_REPOSITORY to win", root.Repository.Repository)
	}
}

func TestMissingRequiredCredentials(t *testing.T) {
	_, err := parseCLI(t, "container", "--image", "app", "--tag", "1.0", "--output", "o.sarif")
	if err == nil || !strings.Contains(err.Error(), "client-id") {
		t.Fatalf("expected missing client-id error, got %v", err)
	}
}

func TestExitCodeOneRejected(t *testing.T) {
	args := append(minimalContainerArgs, "--fail-severity", "high", "--exit-code", "1")
	_, err := parseCLI(t, args...)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved exit code error, got %v", err)
	}
}

func TestExitCodeIgnoredWithoutGate(t *testing.T) {
	// Without --fail-severity the gate is disabled and the exit code value
	// is irrelevant, so it must not be validated.
	args := append(minimalContainerArgs, "--exit-code", "1")
	if _, err := parseCLI(t, args...); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func TestInvalidFailSeverity(t *testing.T) {
	for _, bad := range []string{"severe", "unknown", "info", "CRITICALISH"} {
		args := append(minimalContainerArgs, "--fail-severity", bad)
		if _, err := parseCLI(t, args...); err == nil {
			t.Errorf("fail-severity %q accepted, want error", bad)
		}
	}
	for _, good := range []string{"critical", "HIGH", "medium", "low"} {
		args := append(minimalContainerArgs, "--fail-severity", good)
		if _, err := parseCLI(t, args...); err != nil {
			t.Errorf("fail-severity %q rejected: %v", good, err)
		}
	}
}

func TestConflictingImageTagRejectedAtParse(t *testing.T) {
	_, err := parseCLI(t,
		"container", "--image", "app:1.0", "--tag", "2.0",
		"--output", "o.sarif", "--client-id", "i", "--client-secret", "s")
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("expected conflicting tags error, got %v", err)
	}
}

func TestMissingTagRejectedAtParse(t *testing.T) {
	_, err := parseCLI(t,
		"container", "--image", "app",
		"--output", "o.sarif", "--client-id", "i", "--client-secret", "s")
	if err == nil || !strings.Contains(err.Error(), "tag") {
		t.Fatalf("expected missing tag error, got %v", err)
	}
}

func TestScanTypesParsing(t *testing.T) {
	t.Setenv("AIKIDO_SCAN_TYPES", "sast,secrets")
	root, err := parseCLI(t,
		"repository", "--repository", "r", "--output", "o.sarif", "--client-id", "i", "--client-secret", "s")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	types, err := root.Repository.scanTypes()
	if err != nil {
		t.Fatal(err)
	}
	if !types.SAST || !types.Secrets || types.IaC {
		t.Errorf("scan types = %+v", types)
	}
}

func TestInvalidScanTypeRejected(t *testing.T) {
	_, err := parseCLI(t,
		"repository", "--repository", "r", "--scan-types", "sast,bogus",
		"--output", "o.sarif", "--client-id", "i", "--client-secret", "s")
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("expected invalid scan type error, got %v", err)
	}
}

func TestPipeModeArgs(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	if args, err := PipeModeArgs(env(map[string]string{"AIKIDO_REPORT_TYPE": "container"})); err != nil || len(args) != 1 || args[0] != "container" {
		t.Errorf("container: args=%v err=%v", args, err)
	}
	if args, err := PipeModeArgs(env(map[string]string{"AIKIDO_REPORT_TYPE": "repository"})); err != nil || len(args) != 1 || args[0] != "repository" {
		t.Errorf("repository: args=%v err=%v", args, err)
	}
	if args, err := PipeModeArgs(env(nil)); err != nil || args != nil {
		t.Errorf("unset: args=%v err=%v", args, err)
	}
	if _, err := PipeModeArgs(env(map[string]string{"AIKIDO_REPORT_TYPE": "bogus"})); err == nil {
		t.Error("bogus type accepted")
	}
}
