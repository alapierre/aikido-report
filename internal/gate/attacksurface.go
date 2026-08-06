package gate

import (
	"log/slog"

	"github.com/alapierre/aikido-report/internal/report"
)

// containerAttackSurface is Aikido's attack_surface value for findings
// that describe a container image layer.
const containerAttackSurface = "docker_container"

// dropContainerAttackSurface removes findings that only describe a
// container image (attack_surface "docker_container") from a repository
// report. Aikido links a code repository to its built container image, and
// issues/export for the code repository also returns issues natively
// belonging to that linked container. In CI pipelines that scan the
// repository before the image is even built, those findings describe some
// unrelated (often stale) image, not the commit under test — they are
// dropped unconditionally, regardless of whether they happen to overlap
// with anything in the repository's own manifests. keepAll disables
// filtering (escape hatch). The reverse (container export returning
// code-native findings) has not been observed and is deliberately not
// filtered here.
func dropContainerAttackSurface(logger *slog.Logger, findings []report.Finding, keepAll bool) []report.Finding {
	if keepAll {
		return findings
	}
	kept := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		if f.AttackSurface == containerAttackSurface {
			continue
		}
		kept = append(kept, f)
	}
	if dropped := len(findings) - len(kept); dropped > 0 {
		logger.Info("dropped container-image findings from the repository export",
			"dropped", dropped, "kept", len(kept))
	}
	return kept
}
