// Command aikido-report generates SARIF 2.1.0 reports from Aikido
// Security scan results and can act as a CI quality gate. This is an
// unofficial tool, not affiliated with Aikido Security.
package main

import (
	"fmt"
	"os"

	"github.com/alapierre/aikido-report/internal/cli"
)

// Injected by GoReleaser via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	versionString := fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
	os.Exit(cli.Main(os.Args[1:], versionString, os.Stdout, os.Stderr))
}
