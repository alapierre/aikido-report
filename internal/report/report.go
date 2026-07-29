// Package report defines the domain model shared by scan-target use cases
// and the SARIF generator: a Report describes a scanned target and its
// findings in a shape independent from any Aikido API response format.
//
// The package has no dependencies on API clients, SARIF, or the CLI layer.
package report

import "sort"

// TargetKind identifies what kind of artifact was scanned.
type TargetKind string

const (
	// TargetContainer is a container image in a registry.
	TargetContainer TargetKind = "container"
	// TargetRepository is a source code repository.
	TargetRepository TargetKind = "repository"
)

// Target describes the artifact the findings apply to. Only the fields
// relevant to the Kind are populated: Image/Tag/Registry for containers,
// Repository/Branch/Commit for code repositories.
type Target struct {
	Kind TargetKind

	// Name is the matched Aikido entity name (container repo or code repo).
	Name string

	// Container fields.
	Registry string
	Image    string
	Tag      string

	// Repository fields. Commit is informational metadata only: the Aikido
	// public API does not expose per-commit scans, so it is recorded in the
	// report but never verified against Aikido.
	Repository string
	Branch     string
	Commit     string

	// ReportURL links to the scanned entity in the Aikido dashboard.
	ReportURL string
}

// Report is the complete result of one gate run: the resolved target and
// all findings fetched for it.
type Report struct {
	Target   Target
	Findings []Finding
}

// SortFindings orders findings deterministically: by rule ID, then file,
// then start line, then Aikido issue ID. Identical input always produces
// the same order regardless of API response ordering.
func (r *Report) SortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.ID < b.ID
	})
}

// CountAtLeast returns the number of findings with severity equal to or
// higher than the threshold. Findings with unknown severity never count.
func (r *Report) CountAtLeast(threshold Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity != SeverityUnknown && f.Severity.AtLeast(threshold) {
			n++
		}
	}
	return n
}
