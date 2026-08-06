package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alapierre/aikido-report/internal/report"
)

// fakeAikido spins up a minimal Aikido public API for end-to-end CLI runs.
func fakeAikido(t *testing.T, issues string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if _, secret, _ := r.BasicAuth(); secret != "e2e-secret" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600,"token_type":"bearer"}`))
	})
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":101,"name":"application","registry_name":"registry.example.com",
			"last_scanned_tag":"1.2.3","last_scanned_at":1753700000,"is_active":true,"is_empty":false}]`))
	})
	mux.HandleFunc("GET /api/public/v1/repositories/code", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":55,"name":"my-project","provider":"bitbucket","branch":"master",
			"url":"https://bitbucket.org/acme/my-project","last_scanned_at":1753700000,"active":true}]`))
	})
	mux.HandleFunc("GET /api/public/v1/issues/export", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(issues))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

const criticalIssue = `[{"id":1,"group_id":10,"type":"open_source","rule":"Vulnerable dependency",
	"severity":"critical","severity_score":95,"cve_id":"CVE-2025-1","affected_package":"openssl",
	"installed_version":"1.0","patched_versions":["1.1"],"container_repo_id":101,"code_repo_id":55}]`

const lowIssue = `[{"id":2,"group_id":11,"type":"iac","rule":"Minor misconfiguration",
	"severity":"low","severity_score":20,"container_repo_id":101,"code_repo_id":55}]`

func runMain(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = Main(args, "e2e-test", &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func containerArgs(srv *httptest.Server, output string, extra ...string) []string {
	args := []string{
		"container",
		"--image", "registry.example.com/team/application",
		"--tag", "1.2.3",
		"--output", output,
		"--client-id", "e2e-id",
		"--client-secret", "e2e-secret",
		"--base-url", srv.URL,
	}
	return append(args, extra...)
}

func TestEndToEndContainerGatePasses(t *testing.T) {
	srv := fakeAikido(t, lowIssue)
	out := filepath.Join(t.TempDir(), "report.sarif")
	code, stdout, stderr := runMain(t, containerArgs(srv, out, "--fail-severity", "high")...)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout must stay empty when writing to a file, got %q", stdout)
	}
	assertSARIFFile(t, out, 1)
}

func TestEndToEndContainerGateFails(t *testing.T) {
	srv := fakeAikido(t, criticalIssue)
	out := filepath.Join(t.TempDir(), "report.sarif")
	code, _, stderr := runMain(t, containerArgs(srv, out, "--fail-severity", "high")...)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "quality gate failed") {
		t.Errorf("stderr missing gate message: %s", stderr)
	}
	// The report must exist even though the gate failed.
	assertSARIFFile(t, out, 1)
}

func TestEndToEndCustomExitCode(t *testing.T) {
	srv := fakeAikido(t, criticalIssue)
	out := filepath.Join(t.TempDir(), "report.sarif")
	code, _, _ := runMain(t, containerArgs(srv, out, "--fail-severity", "critical", "--exit-code", "42")...)
	if code != 42 {
		t.Fatalf("exit code = %d, want 42", code)
	}
}

func TestEndToEndGateDisabledByDefault(t *testing.T) {
	srv := fakeAikido(t, criticalIssue)
	out := filepath.Join(t.TempDir(), "report.sarif")
	code, _, stderr := runMain(t, containerArgs(srv, out)...)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (gate disabled); stderr: %s", code, stderr)
	}
	assertSARIFFile(t, out, 1)
}

func TestEndToEndFindingBelowThreshold(t *testing.T) {
	srv := fakeAikido(t, lowIssue)
	out := filepath.Join(t.TempDir(), "report.sarif")
	code, _, _ := runMain(t, containerArgs(srv, out, "--fail-severity", "medium")...)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestEndToEndStdoutOutput(t *testing.T) {
	srv := fakeAikido(t, criticalIssue)
	code, stdout, stderr := runMain(t, containerArgs(srv, "-")...)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr)
	}
	// stdout must contain exactly the SARIF document and nothing else.
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	if stderr == "" {
		t.Error("operational logs should go to stderr")
	}
}

func TestEndToEndTechnicalErrorNoReport(t *testing.T) {
	srv := fakeAikido(t, criticalIssue)
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")
	args := []string{
		"container",
		"--image", "registry.example.com/team/application",
		"--tag", "1.2.3",
		"--output", out,
		"--client-id", "e2e-id",
		"--client-secret", "wrong-secret",
		"--base-url", srv.URL,
		"--fail-severity", "high",
	}
	code, _, stderr := runMain(t, args...)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr: %s", code, stderr)
	}
	if strings.Contains(stderr, "wrong-secret") {
		t.Error("stderr leaks the client secret")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("no report or partial file may exist after a technical error, found: %v", entries)
	}
}

func TestEndToEndScanNotReadyIsExitOne(t *testing.T) {
	srv := fakeAikido(t, criticalIssue)
	out := filepath.Join(t.TempDir(), "report.sarif")
	args := []string{
		"container",
		"--image", "registry.example.com/team/application",
		"--tag", "9.9.9", // not the scanned tag
		"--output", out,
		"--client-id", "e2e-id",
		"--client-secret", "e2e-secret",
		"--base-url", srv.URL,
		"--no-wait",
	}
	code, _, stderr := runMain(t, args...)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "1.2.3") {
		t.Errorf("error should mention the last scanned tag, stderr: %s", stderr)
	}
}

func TestEndToEndRepositoryRelease(t *testing.T) {
	srv := fakeAikido(t, criticalIssue)
	out := filepath.Join(t.TempDir(), "report.sarif")
	args := []string{
		"repository",
		"--repository", "my-project",
		"--branch", "master",
		"--commit", "abc123",
		"--output", out,
		"--client-id", "e2e-id",
		"--client-secret", "e2e-secret",
		"--base-url", srv.URL,
		"--fail-severity", "high",
	}
	code, _, stderr := runMain(t, args...)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr: %s", code, stderr)
	}
	data := assertSARIFFile(t, out, 1)
	if !strings.Contains(string(data), "abc123") {
		t.Error("report should carry the commit metadata")
	}
}

const mixedAttackSurfaceIssues = `[
	{"id":1,"group_id":1,"type":"open_source","attack_surface":"docker_container",
	 "severity":"critical","affected_file":"app/libs/x.jar","container_repo_id":101,"code_repo_id":55},
	{"id":2,"group_id":1,"type":"open_source","attack_surface":"backend",
	 "severity":"low","affected_file":"pom.xml","container_repo_id":101,"code_repo_id":55}
]`

func TestEndToEndRepositoryDropsContainerAttackSurfaceByDefault(t *testing.T) {
	srv := fakeAikido(t, mixedAttackSurfaceIssues)
	out := filepath.Join(t.TempDir(), "report.sarif")
	args := []string{
		"repository",
		"--repository", "my-project",
		"--output", out,
		"--client-id", "e2e-id",
		"--client-secret", "e2e-secret",
		"--base-url", srv.URL,
		"--fail-severity", "critical",
	}
	code, _, stderr := runMain(t, args...)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (the only critical finding is a container-image duplicate); stderr: %s", code, stderr)
	}
	assertSARIFFile(t, out, 1)
}

func TestEndToEndRepositoryIncludeCrossTargetFindings(t *testing.T) {
	srv := fakeAikido(t, mixedAttackSurfaceIssues)
	out := filepath.Join(t.TempDir(), "report.sarif")
	args := []string{
		"repository",
		"--repository", "my-project",
		"--output", out,
		"--client-id", "e2e-id",
		"--client-secret", "e2e-secret",
		"--base-url", srv.URL,
		"--fail-severity", "critical",
		"--include-cross-target-findings",
	}
	code, _, stderr := runMain(t, args...)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (container-image finding kept); stderr: %s", code, stderr)
	}
	assertSARIFFile(t, out, 2)
}

func TestEndToEndPipeMode(t *testing.T) {
	srv := fakeAikido(t, lowIssue)
	out := filepath.Join(t.TempDir(), "report.sarif")
	t.Setenv("AIKIDO_REPORT_TYPE", "container")
	t.Setenv("AIKIDO_IMAGE", "registry.example.com/team/application")
	t.Setenv("AIKIDO_TAG", "1.2.3")
	t.Setenv("AIKIDO_OUTPUT", out)
	t.Setenv("AIKIDO_CLIENT_ID", "e2e-id")
	t.Setenv("AIKIDO_CLIENT_SECRET", "e2e-secret")
	t.Setenv("AIKIDO_BASE_URL", srv.URL)

	code, _, stderr := runMain(t) // no argv, pipe style
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr)
	}
	assertSARIFFile(t, out, 1)
}

func TestEndToEndInvalidPipeType(t *testing.T) {
	t.Setenv("AIKIDO_REPORT_TYPE", "bogus")
	code, _, stderr := runMain(t)
	if code != 1 || !strings.Contains(stderr, "AIKIDO_REPORT_TYPE") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestEndToEndUsageErrorIsExitOne(t *testing.T) {
	code, _, stderr := runMain(t, "container") // missing everything
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "--help") {
		t.Errorf("stderr should point at --help: %s", stderr)
	}
}

func TestVersionFlag(t *testing.T) {
	code, stdout, _ := runMain(t, "--version")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "e2e-test") {
		t.Errorf("version output = %q", stdout)
	}
}

func TestEvaluateGate(t *testing.T) {
	rep := report.Report{Findings: []report.Finding{
		{Severity: report.SeverityHigh},
		{Severity: report.SeverityLow},
	}}
	if err := evaluateGate(rep, "", 2); err != nil {
		t.Errorf("disabled gate returned %v", err)
	}
	if err := evaluateGate(rep, report.SeverityCritical, 2); err != nil {
		t.Errorf("gate above findings returned %v", err)
	}
	err := evaluateGate(rep, report.SeverityHigh, 7)
	var exitErr *ExitCodeError
	if err == nil || !errors.As(err, &exitErr) || exitErr.Code != 7 {
		t.Fatalf("gate at threshold: %v", err)
	}
	if !strings.Contains(exitErr.Message, "1 open finding") {
		t.Errorf("message = %q", exitErr.Message)
	}
}

func assertSARIFFile(t *testing.T, path string, wantResults int) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("report not written: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q", doc.Version)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != wantResults {
		t.Errorf("unexpected results count: %s", fmt.Sprint(len(doc.Runs[0].Results)))
	}
	return data
}
