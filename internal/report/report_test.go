package report

import (
	"slices"
	"testing"
)

func TestSortFindingsDeterministic(t *testing.T) {
	r := Report{Findings: []Finding{
		{RuleID: "CVE-2024-2", ID: "5"},
		{RuleID: "CVE-2024-1", File: "b.go", StartLine: 3, ID: "4"},
		{RuleID: "CVE-2024-1", File: "a.go", StartLine: 10, ID: "3"},
		{RuleID: "CVE-2024-1", File: "a.go", StartLine: 2, ID: "2"},
		{RuleID: "CVE-2024-1", File: "a.go", StartLine: 2, ID: "1"},
	}}
	r.SortFindings()

	gotIDs := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		gotIDs = append(gotIDs, f.ID)
	}
	want := []string{"1", "2", "3", "4", "5"}
	if !slices.Equal(gotIDs, want) {
		t.Errorf("sorted IDs = %v, want %v", gotIDs, want)
	}

	// Sorting an already sorted report must not change the order.
	r.SortFindings()
	gotIDs = gotIDs[:0]
	for _, f := range r.Findings {
		gotIDs = append(gotIDs, f.ID)
	}
	if !slices.Equal(gotIDs, want) {
		t.Errorf("second sort changed order: %v", gotIDs)
	}
}

func TestCountAtLeast(t *testing.T) {
	r := Report{Findings: []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityLow},
		{Severity: SeverityUnknown},
	}}
	tests := []struct {
		threshold Severity
		want      int
	}{
		{SeverityCritical, 1},
		{SeverityHigh, 2},
		{SeverityMedium, 3},
		{SeverityLow, 4},
		// Unknown findings never count, even against the lowest threshold.
		{SeverityInfo, 4},
	}
	for _, tt := range tests {
		if got := r.CountAtLeast(tt.threshold); got != tt.want {
			t.Errorf("CountAtLeast(%q) = %d, want %d", tt.threshold, got, tt.want)
		}
	}
}

func TestRuleID(t *testing.T) {
	tests := []struct {
		cve, ruleID, typ, groupID string
		want                      string
	}{
		{"CVE-2024-1234", "aik_sast_001", "sast", "42", "CVE-2024-1234"},
		{"", "aik_sast_001", "sast", "42", "aik_sast_001"},
		{"", "", "open_source", "42", "aikido-open_source-42"},
	}
	for _, tt := range tests {
		if got := RuleID(tt.cve, tt.ruleID, tt.typ, tt.groupID); got != tt.want {
			t.Errorf("RuleID(%q,%q,%q,%q) = %q, want %q", tt.cve, tt.ruleID, tt.typ, tt.groupID, got, tt.want)
		}
	}
}
