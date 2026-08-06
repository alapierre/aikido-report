package gate

import (
	"testing"

	"github.com/alapierre/aikido-report/internal/report"
)

func TestDropContainerAttackSurface(t *testing.T) {
	findings := []report.Finding{
		{ID: "1", AttackSurface: "docker_container"},
		{ID: "2", AttackSurface: "backend"},
		{ID: "3", AttackSurface: "cloud"},
		{ID: "4", AttackSurface: ""},
		{ID: "5", AttackSurface: "docker_container"},
	}

	kept := dropContainerAttackSurface(testLogger(), findings, false)
	var gotIDs []string
	for _, f := range kept {
		gotIDs = append(gotIDs, f.ID)
	}
	wantIDs := []string{"2", "3", "4"}
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("kept = %v, want %v", gotIDs, wantIDs)
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Errorf("kept = %v, want %v", gotIDs, wantIDs)
		}
	}
}

func TestDropContainerAttackSurfaceKeepAll(t *testing.T) {
	findings := []report.Finding{
		{ID: "1", AttackSurface: "docker_container"},
		{ID: "2", AttackSurface: "backend"},
	}
	kept := dropContainerAttackSurface(testLogger(), findings, true)
	if len(kept) != len(findings) {
		t.Fatalf("keepAll must be a no-op, got %d findings, want %d", len(kept), len(findings))
	}
}

func TestDropContainerAttackSurfaceNoneDropped(t *testing.T) {
	findings := []report.Finding{
		{ID: "1", AttackSurface: "backend"},
		{ID: "2", AttackSurface: ""},
	}
	kept := dropContainerAttackSurface(testLogger(), findings, false)
	if len(kept) != 2 {
		t.Fatalf("got %d findings, want 2 (nothing to drop)", len(kept))
	}
}
