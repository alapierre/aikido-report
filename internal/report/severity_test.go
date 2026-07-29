package report

import "testing"

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want Severity
	}{
		{"critical", SeverityCritical},
		{"CRITICAL", SeverityCritical},
		{" High ", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"info", SeverityInfo},
		{"", SeverityUnknown},
		{"severe", SeverityUnknown},
		{"HIGHEST", SeverityUnknown},
	}
	for _, tt := range tests {
		if got := ParseSeverity(tt.in); got != tt.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		s, threshold Severity
		want         bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityCritical, false},
		{SeverityUnknown, SeverityLow, false},
		{SeverityInfo, SeverityInfo, true},
	}
	for _, tt := range tests {
		if got := tt.s.AtLeast(tt.threshold); got != tt.want {
			t.Errorf("%q.AtLeast(%q) = %v, want %v", tt.s, tt.threshold, got, tt.want)
		}
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	order := []Severity{SeverityUnknown, SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Errorf("expected %q to rank above %q", order[i], order[i-1])
		}
	}
}
