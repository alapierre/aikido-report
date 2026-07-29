package sarifgen

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alapierre/aikido-report/internal/report"
)

const (
	defaultToolName       = "aikido-report"
	defaultInformationURI = "https://github.com/alapierre/aikido-report"
	// reportFileMode is deliberately world-readable: in Bitbucket
	// Pipelines the report is consumed by other pipe containers.
	reportFileMode = 0o644
)

// Generator writes SARIF 2.1.0 documents for domain reports.
type Generator struct {
	// ToolName and InformationURI have sensible defaults; ToolVersion
	// should carry the CLI version injected at build time.
	ToolName       string
	ToolVersion    string
	InformationURI string
}

func (g *Generator) toolName() string {
	if g.ToolName != "" {
		return g.ToolName
	}
	return defaultToolName
}

func (g *Generator) informationURI() string {
	if g.InformationURI != "" {
		return g.InformationURI
	}
	return defaultInformationURI
}

// Write renders the report as indented, deterministic JSON to dst.
func (g *Generator) Write(rep report.Report, dst io.Writer) error {
	doc := g.build(rep)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("sarifgen: encoding SARIF document: %w", err)
	}
	data = append(data, '\n')
	if _, err := dst.Write(data); err != nil {
		return fmt.Errorf("sarifgen: writing SARIF document: %w", err)
	}
	return nil
}

// WriteFile writes the report atomically: the document is fully written
// and synced to a temporary file in the destination directory, then
// renamed into place. A failed run never leaves a partial report behind.
func (g *Generator) WriteFile(rep report.Report, path string) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".aikido-report-*.tmp")
	if err != nil {
		return fmt.Errorf("sarifgen: creating temporary file in %q: %w", dir, err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	if err = g.Write(rep, tmp); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sarifgen: syncing %q: %w", tmp.Name(), err)
	}
	if err = tmp.Chmod(reportFileMode); err != nil {
		return fmt.Errorf("sarifgen: setting permissions on %q: %w", tmp.Name(), err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("sarifgen: closing %q: %w", tmp.Name(), err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("sarifgen: renaming report into place: %w", err)
	}
	return nil
}
