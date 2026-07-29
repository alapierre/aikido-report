package gate

import (
	"strings"
	"testing"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
	"github.com/alapierre/aikido-report/internal/report"
)

func TestFindingRuleIDPrecedence(t *testing.T) {
	tests := []struct {
		name  string
		issue publicapi.Issue
		want  string
	}{
		{"cve wins", publicapi.Issue{CVEID: "CVE-2025-1", RuleID: "aik_x", Type: "open_source", GroupID: 7}, "CVE-2025-1"},
		{"aikido rule id", publicapi.Issue{RuleID: "aik_sast_001", Type: "sast", GroupID: 7}, "aik_sast_001"},
		{"stable fallback", publicapi.Issue{Type: "sast", GroupID: 7}, "aikido-sast-7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := findingFromIssue(tt.issue, "")
			if f.RuleID != tt.want {
				t.Errorf("RuleID = %q, want %q", f.RuleID, tt.want)
			}
		})
	}
}

func TestFindingDashboardURL(t *testing.T) {
	f := findingFromIssue(publicapi.Issue{ID: 1, GroupID: 42, Type: "sast"}, "https://app.aikido.dev/")
	if f.URL != "https://app.aikido.dev/issues/42/detail" {
		t.Errorf("URL = %q", f.URL)
	}
	f = findingFromIssue(publicapi.Issue{ID: 1, Type: "sast"}, "https://app.aikido.dev")
	if f.URL != "" {
		t.Errorf("URL without group id = %q, want empty", f.URL)
	}
}

func TestFindingTitle(t *testing.T) {
	tests := []struct {
		issue publicapi.Issue
		want  string
	}{
		{publicapi.Issue{Rule: "Vulnerable dependency", AffectedPackage: "openssl"}, "Vulnerable dependency: openssl"},
		{publicapi.Issue{Rule: "SQL Injection"}, "SQL Injection"},
		{publicapi.Issue{AffectedPackage: "openssl"}, "Vulnerable package: openssl"},
		{publicapi.Issue{CVEID: "CVE-2025-1"}, "CVE-2025-1"},
		{publicapi.Issue{}, "Aikido finding"},
	}
	for _, tt := range tests {
		if got := issueTitle(tt.issue); got != tt.want {
			t.Errorf("issueTitle(%+v) = %q, want %q", tt.issue, got, tt.want)
		}
	}
}

func TestFindingDescription(t *testing.T) {
	issue := publicapi.Issue{
		AffectedPackage:  "openssl",
		InstalledVersion: "3.0.11",
		PatchedVersions:  []string{"3.0.14", "3.1.6"},
		CVEID:            "CVE-2025-12345",
		CWEClasses:       []string{"CWE-787"},
		Exploitability:   "actively_exploited",
	}
	got := issueDescription(issue)
	for _, part := range []string{"openssl", "3.0.11", "3.0.14, 3.1.6", "CVE-2025-12345", "CWE-787", "actively exploited"} {
		if !strings.Contains(got, part) {
			t.Errorf("description %q missing %q", got, part)
		}
	}
	if issueDescription(publicapi.Issue{}) != "" {
		t.Errorf("empty issue should produce empty description")
	}
}

func TestFindingKeepsUnknownSeverity(t *testing.T) {
	f := findingFromIssue(publicapi.Issue{ID: 1, GroupID: 2, Type: "sast", Severity: "brand-new-level"}, "")
	if f.Severity != report.SeverityUnknown {
		t.Errorf("Severity = %q, want unknown", f.Severity)
	}
}

func TestFindingFieldMapping(t *testing.T) {
	issue := publicapi.Issue{
		ID: 9001, GroupID: 501, Type: "open_source", Rule: "Vulnerable dependency",
		Severity: "critical", SeverityScore: 95,
		AffectedPackage: "openssl", AffectedFile: "go.mod",
		CVEID: "CVE-2025-12345", CWEClasses: []string{"CWE-787"},
		StartLine: 3, EndLine: 3,
		InstalledVersion: "3.0.11", PatchedVersions: []string{"3.0.14"},
		ProgrammingLanguage: "GO", Exploitability: "poc_exists",
	}
	f := findingFromIssue(issue, "https://app.aikido.dev")
	if f.ID != "9001" || f.GroupID != "501" || f.SeverityScore != 95 ||
		f.File != "go.mod" || f.StartLine != 3 || f.EndLine != 3 ||
		f.PackageName != "openssl" || f.InstalledVersion != "3.0.11" ||
		f.Language != "GO" || f.Exploitability != "poc_exists" {
		t.Errorf("field mapping wrong: %+v", f)
	}
	if f.Properties != nil {
		t.Errorf("known category must not set properties: %+v", f.Properties)
	}
}
