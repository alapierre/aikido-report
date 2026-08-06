package report

import "fmt"

// Finding is one security issue in the domain model. All fields are plain
// data mapped from an Aikido issue; optional information is represented by
// zero values, never by artificial placeholders.
type Finding struct {
	// ID is the Aikido issue ID.
	ID string
	// GroupID is the Aikido issue group ID (issues are grouped per problem).
	GroupID string
	// RuleID is the stable SARIF rule identifier, see RuleID().
	RuleID string
	// RuleName is the human-readable Aikido rule, e.g. "SQL Injection".
	RuleName string

	Category Category
	// AikidoType is the original Aikido issue type, kept verbatim so that
	// CategoryUnknown findings remain diagnosable.
	AikidoType string
	// AttackSurface is Aikido's raw classification of where the finding
	// applies (e.g. "docker_container", "backend"); empty when absent.
	AttackSurface string

	Severity Severity
	// SeverityScore is Aikido's 1-100 score; 0 when absent.
	SeverityScore int

	Title       string
	Description string

	// Source location; empty/zero when the finding has no natural file
	// (typical for container findings). The SARIF generator emits no
	// location in that case.
	File      string
	StartLine int
	EndLine   int

	// Package metadata for dependency findings.
	PackageName      string
	InstalledVersion string
	PatchedVersions  []string

	CVE  string
	CWEs []string

	Language       string
	Exploitability string

	// URL links to the issue in the Aikido dashboard.
	URL string

	// Properties carries additional non-standard metadata. It must never
	// contain secrets.
	Properties map[string]string
}

// RuleID derives a deterministic SARIF rule identifier. Precedence:
// CVE, then the Aikido rule ID, then a stable fallback built from the
// issue type and group ID. No random or time-based components.
func RuleID(cve, aikidoRuleID, aikidoType, groupID string) string {
	if cve != "" {
		return cve
	}
	if aikidoRuleID != "" {
		return aikidoRuleID
	}
	return fmt.Sprintf("aikido-%s-%s", aikidoType, groupID)
}
