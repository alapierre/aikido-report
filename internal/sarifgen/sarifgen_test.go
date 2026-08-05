package sarifgen

import (
	"bytes"
	"errors"
	"flag"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/alapierre/aikido-report/internal/report"
)

var update = flag.Bool("update", false, "rewrite golden files")

func testGenerator() *Generator {
	return &Generator{ToolVersion: "1.2.3-test"}
}

// containerReport exercises container-style findings: package metadata,
// no source locations, unicode, unknown severity/category, a finding with
// an absolute in-image path that must not surface as a SARIF location,
// and a finding with a relative in-image path that keeps its location.
func containerReport() report.Report {
	return report.Report{
		Target: report.Target{
			Kind:      report.TargetContainer,
			Name:      "application",
			Registry:  "registry.example.com",
			Image:     "team/application",
			Tag:       "1.2.3",
			ReportURL: "https://app.aikido.dev/container/101",
		},
		Findings: []report.Finding{
			{
				ID: "9001", GroupID: "501", RuleID: "CVE-2025-12345",
				RuleName: "Vulnerable dependency", Category: report.CategorySCA,
				AikidoType: "open_source", Severity: report.SeverityCritical, SeverityScore: 95,
				Title:       "Vulnerable dependency: openssl",
				Description: "Affected package: openssl (installed 3.0.11, fixed in 3.0.14, 3.1.6). CVE-2025-12345. CWE-787. A proof-of-concept exploit exists.",
				PackageName: "openssl", InstalledVersion: "3.0.11",
				PatchedVersions: []string{"3.0.14", "3.1.6"},
				CVE:             "CVE-2025-12345", CWEs: []string{"CWE-787"},
				Exploitability: "poc_exists",
				URL:            "https://app.aikido.dev/issues/501/detail",
			},
			{
				ID: "9002", GroupID: "502", RuleID: "CVE-2025-99999",
				RuleName: "Vulnerable dependency", Category: report.CategorySCA,
				AikidoType: "open_source", Severity: report.SeverityHigh, SeverityScore: 80,
				Title:       "Vulnerable dependency: log4j-api",
				Description: "Affected package: log4j-api (installed 2.25.4). CVE-2025-99999.",
				File:        "/app/libs/log4j-api-2.25.4.jar",
				PackageName: "log4j-api", InstalledVersion: "2.25.4",
				CVE: "CVE-2025-99999",
				URL: "https://app.aikido.dev/issues/502/detail",
			},
			{
				ID: "9003", GroupID: "503", RuleID: "aik_secret_generic_001",
				RuleName: "Secret detected in container image", Category: report.CategorySecret,
				AikidoType: "leaked_secret", Severity: report.SeverityMedium, SeverityScore: 55,
				Title: "Secret detected in container image",
				File:  "app/config/settings.py", StartLine: 42, EndLine: 42,
				CWEs: []string{"CWE-798"}, Language: "PY",
				URL: "https://app.aikido.dev/issues/503/detail",
			},
			{
				ID: "9007", GroupID: "507", RuleID: "aikido-surface_monitoring-507",
				Category:   report.CategoryUnknown,
				AikidoType: "surface_monitoring", Severity: report.SeverityUnknown,
				Title:      "Zażółć gębską jaźń — ünïcode test \"<&>\"",
				Properties: map[string]string{"aikido_type": "surface_monitoring"},
			},
		},
	}
}

// repositoryReport exercises code-style findings: locations with line
// ranges, long descriptions, missing optional fields, several categories.
func repositoryReport() report.Report {
	return report.Report{
		Target: report.Target{
			Kind:       report.TargetRepository,
			Name:       "my-project",
			Repository: "my-project",
			Branch:     "master",
			Commit:     "0123456789abcdef0123456789abcdef01234567",
			ReportURL:  "https://bitbucket.org/acme/my-project",
		},
		Findings: []report.Finding{
			{
				ID: "7001", GroupID: "601", RuleID: "aik_sast_sqli_001",
				RuleName: "SQL Injection", Category: report.CategorySAST,
				AikidoType: "sast", Severity: report.SeverityHigh, SeverityScore: 80,
				Title: "SQL Injection",
				File:  "internal/db/query.go", StartLine: 118, EndLine: 124,
				CWEs: []string{"CWE-89"}, Language: "GO",
				URL: "https://app.aikido.dev/issues/601/detail",
			},
			{
				ID: "7002", GroupID: "602", RuleID: "CVE-2025-34567",
				RuleName: "Vulnerable dependency", Category: report.CategorySCA,
				AikidoType: "open_source", Severity: report.SeverityCritical, SeverityScore: 92,
				Title:       "Vulnerable dependency: github.com/some/dependency",
				Description: strings.Repeat("Very long description. ", 60),
				File:        "go.mod",
				PackageName: "github.com/some/dependency", InstalledVersion: "1.4.0",
				PatchedVersions: []string{"1.4.9"},
				CVE:             "CVE-2025-34567", CWEs: []string{"CWE-502"},
				Exploitability: "actively_exploited",
				URL:            "https://app.aikido.dev/issues/602/detail",
			},
			{
				ID: "7003", GroupID: "603", RuleID: "aik_iac_aws_042",
				RuleName: "S3 bucket without encryption", Category: report.CategoryIaC,
				AikidoType: "iac", Severity: report.SeverityLow, SeverityScore: 30,
				Title: "S3 bucket without encryption",
				File:  "deploy/terraform/storage.tf", StartLine: 12, EndLine: 25,
				URL: "https://app.aikido.dev/issues/603/detail",
			},
			{
				// Minimal finding: no optional fields at all.
				ID: "7009", GroupID: "609", RuleID: "aikido-eol-609",
				Category: report.CategoryEOL, AikidoType: "eol",
				Severity: report.SeverityInfo,
				Title:    "End-of-life runtime",
			},
		},
	}
}

func goldenTest(t *testing.T, name string, rep report.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := testGenerator().Write(rep, &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	golden := filepath.Join("..", "..", "testdata", "sarif", name)
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("updating golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("output differs from %s (run with -update after intentional changes)", golden)
	}
	return buf.Bytes()
}

func TestGoldenContainerReport(t *testing.T) {
	data := goldenTest(t, "container.sarif.json", containerReport())
	assertValidSARIF(t, data)
}

func TestGoldenRepositoryReport(t *testing.T) {
	data := goldenTest(t, "repository.sarif.json", repositoryReport())
	assertValidSARIF(t, data)
}

func TestGoldenEmptyReport(t *testing.T) {
	rep := report.Report{Target: report.Target{Kind: report.TargetContainer, Name: "app", Tag: "1.0"}}
	data := goldenTest(t, "empty.sarif.json", rep)
	assertValidSARIF(t, data)
}

func assertValidSARIF(t *testing.T, data []byte) {
	t.Helper()
	doc, err := sarif.FromBytes(data)
	if err != nil {
		t.Fatalf("parsing produced SARIF: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Errorf("SARIF schema validation failed: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q", doc.Version)
	}
}

func TestDeterministicAcrossInputOrder(t *testing.T) {
	base := repositoryReport()
	var first bytes.Buffer
	if err := testGenerator().Write(base, &first); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		shuffled := repositoryReport()
		rand.New(rand.NewSource(int64(i))).Shuffle(len(shuffled.Findings), func(a, b int) {
			shuffled.Findings[a], shuffled.Findings[b] = shuffled.Findings[b], shuffled.Findings[a]
		})
		var buf bytes.Buffer
		if err := testGenerator().Write(shuffled, &buf); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), buf.Bytes()) {
			t.Fatalf("output depends on findings input order (shuffle %d)", i)
		}
	}
}

func TestNoTimestampsInOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := testGenerator().Write(containerReport(), &buf); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"TimeUtc", "startTime", "endTime"} {
		if strings.Contains(buf.String(), forbidden) {
			t.Errorf("output contains time field %q", forbidden)
		}
	}
}

func TestToolMetadata(t *testing.T) {
	var buf bytes.Buffer
	if err := testGenerator().Write(containerReport(), &buf); err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	driver := doc.Runs[0].Tool.Driver
	if *driver.Name != "aikido-report" || *driver.Version != "1.2.3-test" {
		t.Errorf("driver = %s %s", *driver.Name, *driver.Version)
	}
	if !strings.Contains(*driver.InformationURI, "github.com") {
		t.Errorf("InformationURI = %q", *driver.InformationURI)
	}
}

func TestSeverityToLevelMapping(t *testing.T) {
	tests := []struct {
		severity report.Severity
		want     string
	}{
		{report.SeverityCritical, "error"},
		{report.SeverityHigh, "error"},
		{report.SeverityMedium, "warning"},
		{report.SeverityLow, "note"},
		{report.SeverityInfo, "note"},
		{report.SeverityUnknown, "note"},
	}
	for _, tt := range tests {
		if got := level(tt.severity); got != tt.want {
			t.Errorf("level(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestRuleTagsCarrySeverityForConsumers(t *testing.T) {
	var buf bytes.Buffer
	if err := testGenerator().Write(containerReport(), &buf); err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var cveRule *sarif.ReportingDescriptor
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		if *r.ID == "CVE-2025-12345" {
			cveRule = r
		}
	}
	if cveRule == nil {
		t.Fatal("CVE rule not found")
	}
	tags := cveRule.Properties.Tags
	joined := strings.Join(tags, " ")
	for _, want := range []string{"CRITICAL", "sca", "CWE-787"} {
		if !strings.Contains(joined, want) {
			t.Errorf("rule tags %v missing %q", tags, want)
		}
	}
	// security-severity keeps bb-insights' CVSS-based tier working.
	if got, ok := cveRule.Properties.Properties["security-severity"].(float64); !ok || got != 9.5 {
		t.Errorf("security-severity = %v", cveRule.Properties.Properties["security-severity"])
	}
}

func TestRuleIndexPointsAtCorrectRule(t *testing.T) {
	var buf bytes.Buffer
	if err := testGenerator().Write(repositoryReport(), &buf); err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	run := doc.Runs[0]
	for _, res := range run.Results {
		idx := res.RuleIndex
		if idx < 0 || idx >= len(run.Tool.Driver.Rules) {
			t.Fatalf("ruleIndex %d out of range", idx)
		}
		if *run.Tool.Driver.Rules[idx].ID != *res.RuleID {
			t.Errorf("ruleIndex %d points at %q, result says %q", idx, *run.Tool.Driver.Rules[idx].ID, *res.RuleID)
		}
	}
}

func TestFindingWithoutFileHasNoLocations(t *testing.T) {
	var buf bytes.Buffer
	if err := testGenerator().Write(containerReport(), &buf); err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range doc.Runs[0].Results {
		hasPackage := res.Properties != nil && res.Properties.Properties["packageName"] == "openssl"
		if hasPackage && len(res.Locations) != 0 {
			t.Errorf("container package finding must have no locations, got %d", len(res.Locations))
		}
	}
	// Raw JSON must not contain placeholder paths either.
	for _, fake := range []string{"Dockerfile:1", `"uri": "container"`, `"uri": "unknown"`} {
		if strings.Contains(buf.String(), fake) {
			t.Errorf("output contains artificial location %q", fake)
		}
	}
}

// TestAbsoluteFileHasNoLocation guards against Aikido reporting a path
// from inside the scanned filesystem (image layers, OS package databases)
// rather than the source repository: such paths are always absolute,
// while genuine repo-relative paths never are. Bitbucket rejects any
// annotation batch containing an absolute path, so these must never
// surface as a SARIF location — regardless of target kind.
func TestAbsoluteFileHasNoLocation(t *testing.T) {
	var buf bytes.Buffer
	if err := testGenerator().Write(containerReport(), &buf); err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var cve, secret *sarif.Result
	for _, res := range doc.Runs[0].Results {
		switch *res.RuleID {
		case "CVE-2025-99999":
			cve = res
		case "aik_secret_generic_001":
			secret = res
		}
	}
	if cve == nil {
		t.Fatal("CVE-2025-99999 result not found")
	}
	if len(cve.Locations) != 0 {
		t.Errorf("finding with an absolute file path must have no locations, got %d", len(cve.Locations))
	}
	if strings.Contains(buf.String(), "log4j-api-2.25.4.jar") {
		t.Error("in-image path of an absolute-path finding leaked into the output")
	}
	if secret == nil {
		t.Fatal("aik_secret_generic_001 result not found")
	}
	if len(secret.Locations) != 1 {
		t.Fatalf("finding with a relative file path should keep its location, got %d", len(secret.Locations))
	}
	if uri := *secret.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "app/config/settings.py" {
		t.Errorf("uri = %q", uri)
	}
}

// TestAbsoluteFileOnRepositoryTargetHasNoLocation reproduces a real Aikido
// "code repository" scan that embeds container/OS-level findings (e.g. via
// an SBOM of a built image): the target kind is repository, but some
// findings still carry an absolute in-image/system path like
// /var/lib/dpkg/status, which must not become a SARIF location either.
func TestAbsoluteFileOnRepositoryTargetHasNoLocation(t *testing.T) {
	rep := repositoryReport()
	rep.Findings = append(rep.Findings, report.Finding{
		ID: "7010", GroupID: "610", RuleID: "CVE-2025-77777",
		RuleName: "Vulnerable dependency", Category: report.CategorySCA,
		AikidoType: "open_source", Severity: report.SeverityHigh, SeverityScore: 75,
		Title: "Vulnerable dependency: libssl",
		File:  "/var/lib/dpkg/status",
		CVE:   "CVE-2025-77777",
	})
	var buf bytes.Buffer
	if err := testGenerator().Write(rep, &buf); err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range doc.Runs[0].Results {
		if *res.RuleID == "CVE-2025-77777" && len(res.Locations) != 0 {
			t.Errorf("finding with an absolute file path on a repository target must have no locations, got %d", len(res.Locations))
		}
	}
	if strings.Contains(buf.String(), "/var/lib/dpkg/status") {
		t.Error("absolute in-image path leaked into the output")
	}
}

func TestLocationsPreserved(t *testing.T) {
	var buf bytes.Buffer
	if err := testGenerator().Write(repositoryReport(), &buf); err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var sqli *sarif.Result
	for _, res := range doc.Runs[0].Results {
		if *res.RuleID == "aik_sast_sqli_001" {
			sqli = res
		}
	}
	if sqli == nil {
		t.Fatal("sast result not found")
	}
	loc := sqli.Locations[0].PhysicalLocation
	if *loc.ArtifactLocation.URI != "internal/db/query.go" {
		t.Errorf("uri = %q", *loc.ArtifactLocation.URI)
	}
	if *loc.Region.StartLine != 118 || *loc.Region.EndLine != 124 {
		t.Errorf("region = %d-%d", *loc.Region.StartLine, *loc.Region.EndLine)
	}
}

func TestVersionControlProvenanceForRepository(t *testing.T) {
	var buf bytes.Buffer
	if err := testGenerator().Write(repositoryReport(), &buf); err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	vcs := doc.Runs[0].VersionControlProvenance
	if len(vcs) != 1 {
		t.Fatalf("got %d versionControlProvenance entries, want 1", len(vcs))
	}
	if *vcs[0].RevisionID != "0123456789abcdef0123456789abcdef01234567" || *vcs[0].Branch != "master" {
		t.Errorf("vcs = %+v", vcs[0])
	}
}

func TestWriteFileIsAtomicAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.sarif")
	if err := testGenerator().WriteFile(containerReport(), path); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != reportFileMode {
		t.Errorf("mode = %v, want %v", info.Mode().Perm(), os.FileMode(reportFileMode))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertValidSARIF(t, data)
}

func TestWriteFileFailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-subdir", "out.sarif")
	if err := testGenerator().WriteFile(containerReport(), missing); err == nil {
		t.Fatal("expected error for missing directory")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("files left behind: %v", entries)
	}
}

// failingWriter simulates a broken pipe after the first byte.
type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write: broken pipe")
}

func TestWriteToBrokenPipeReturnsError(t *testing.T) {
	err := testGenerator().Write(containerReport(), failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("expected wrapped broken pipe error, got %v", err)
	}
}
