package report

import "strings"

// Severity is the tool's common severity scale. Aikido severities are
// mapped onto it in exactly one place (ParseSeverity) so that the gate,
// the SARIF generator and log output always agree.
type Severity string

// Severity levels from most to least severe.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	// SeverityUnknown is used for values this tool does not recognize.
	// Unknown findings are kept in the report but rank below every known
	// severity and never trip the quality gate.
	SeverityUnknown Severity = "unknown"
)

var severityRank = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
	SeverityUnknown:  0,
}

// ParseSeverity maps an Aikido severity string onto the common scale.
// Matching is case-insensitive; unrecognized values become SeverityUnknown.
func ParseSeverity(s string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	case SeverityInfo:
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// Rank returns the numeric position of the severity; higher is more severe.
func (s Severity) Rank() int {
	return severityRank[s]
}

// AtLeast reports whether s is at least as severe as the threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return s.Rank() >= threshold.Rank()
}
