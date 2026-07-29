package gate

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/alapierre/aikido-report/internal/aikido/publicapi"
	"github.com/alapierre/aikido-report/internal/report"
)

// findingsFromIssues maps Aikido issues onto domain findings. Unknown
// severities and categories are preserved, never dropped.
func findingsFromIssues(issues []publicapi.Issue, dashboardBaseURL string) []report.Finding {
	findings := make([]report.Finding, 0, len(issues))
	for _, issue := range issues {
		findings = append(findings, findingFromIssue(issue, dashboardBaseURL))
	}
	return findings
}

func findingFromIssue(issue publicapi.Issue, dashboardBaseURL string) report.Finding {
	groupID := strconv.Itoa(issue.GroupID)
	f := report.Finding{
		ID:               strconv.Itoa(issue.ID),
		GroupID:          groupID,
		RuleID:           report.RuleID(issue.CVEID, issue.RuleID, issue.Type, groupID),
		RuleName:         issue.Rule,
		Category:         report.CategoryFromAikidoType(issue.Type),
		AikidoType:       issue.Type,
		Severity:         report.ParseSeverity(issue.Severity),
		SeverityScore:    issue.SeverityScore,
		File:             issue.AffectedFile,
		StartLine:        issue.StartLine,
		EndLine:          issue.EndLine,
		PackageName:      issue.AffectedPackage,
		InstalledVersion: issue.InstalledVersion,
		PatchedVersions:  issue.PatchedVersions,
		CVE:              issue.CVEID,
		CWEs:             issue.CWEClasses,
		Language:         issue.ProgrammingLanguage,
		Exploitability:   issue.Exploitability,
	}
	f.Title = issueTitle(issue)
	f.Description = issueDescription(issue)
	if dashboardBaseURL != "" && issue.GroupID != 0 {
		f.URL = fmt.Sprintf("%s/issues/%s/detail", strings.TrimRight(dashboardBaseURL, "/"), groupID)
	}
	if f.Category == report.CategoryUnknown && issue.Type != "" {
		f.Properties = map[string]string{"aikido_type": issue.Type}
	}
	return f
}

// issueTitle builds a short, single-line title. The issues/export endpoint
// carries no free-text title, so it is composed from structured fields.
func issueTitle(issue publicapi.Issue) string {
	switch {
	case issue.Rule != "" && issue.AffectedPackage != "":
		return fmt.Sprintf("%s: %s", issue.Rule, issue.AffectedPackage)
	case issue.Rule != "":
		return issue.Rule
	case issue.AffectedPackage != "":
		return "Vulnerable package: " + issue.AffectedPackage
	case issue.CVEID != "":
		return issue.CVEID
	default:
		return "Aikido finding"
	}
}

// issueDescription assembles the available structured details into a
// readable sentence list.
func issueDescription(issue publicapi.Issue) string {
	var parts []string
	if issue.AffectedPackage != "" {
		s := "Affected package: " + issue.AffectedPackage
		if issue.InstalledVersion != "" {
			s += " (installed " + issue.InstalledVersion
			if len(issue.PatchedVersions) > 0 {
				s += ", fixed in " + strings.Join(issue.PatchedVersions, ", ")
			}
			s += ")"
		} else if len(issue.PatchedVersions) > 0 {
			s += " (fixed in " + strings.Join(issue.PatchedVersions, ", ") + ")"
		}
		parts = append(parts, s+".")
	}
	if issue.CVEID != "" {
		parts = append(parts, issue.CVEID+".")
	}
	if len(issue.CWEClasses) > 0 {
		parts = append(parts, strings.Join(issue.CWEClasses, ", ")+".")
	}
	switch issue.Exploitability {
	case "actively_exploited":
		parts = append(parts, "Known to be actively exploited.")
	case "poc_exists":
		parts = append(parts, "A proof-of-concept exploit exists.")
	}
	return strings.Join(parts, " ")
}
