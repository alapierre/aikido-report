package cli

import (
	"fmt"
	"strings"
)

// PipeModeArgs synthesizes the command-line arguments for Bitbucket pipe
// mode, where the container is started with no argv and configured only by
// environment variables. AIKIDO_REPORT_TYPE selects the subcommand; every
// flag then resolves through its own env fallback.
//
// Returns nil when AIKIDO_REPORT_TYPE is unset, letting the normal
// "expected one of ..." kong error surface.
func PipeModeArgs(getenv func(string) string) ([]string, error) {
	reportType := strings.TrimSpace(getenv("AIKIDO_REPORT_TYPE"))
	switch reportType {
	case "":
		return nil, nil
	case "container", "repository":
		return []string{reportType}, nil
	default:
		return nil, fmt.Errorf("invalid AIKIDO_REPORT_TYPE %q: valid values are container, repository", reportType)
	}
}
