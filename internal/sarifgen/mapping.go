// Package sarifgen turns a domain report.Report into a SARIF 2.1.0
// document. It knows only the domain model: no HTTP, no credentials, no
// polling, no exit-code decisions.
//
// Output is fully deterministic: findings and rules are sorted, no
// timestamps or random identifiers are emitted, and all maps marshal with
// encoding/json's sorted keys. Identical input produces identical bytes.
package sarifgen

import (
	"math"
	"sort"
	"strings"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/alapierre/aikido-report/internal/report"
)

// build maps the domain report onto a SARIF document.
func (g *Generator) build(rep report.Report) *sarif.Report {
	rep.SortFindings()

	run := sarif.NewRun()
	run.Tool = sarif.NewTool()
	run.Tool.Driver = g.driver(rep.Findings)
	run.Results = g.results(rep.Findings)
	run.Properties = runProperties(rep.Target)
	if vcs := versionControl(rep.Target); vcs != nil {
		run.VersionControlProvenance = []*sarif.VersionControlDetails{vcs}
	}

	doc := sarif.NewReport()
	doc.AddRun(run)
	return doc
}

func (g *Generator) driver(findings []report.Finding) *sarif.ToolComponent {
	driver := sarif.NewToolComponent()
	driver.Name = ptr(g.toolName())
	driver.InformationURI = ptr(g.informationURI())
	if g.ToolVersion != "" {
		driver.Version = ptr(g.ToolVersion)
	}
	driver.Rules = rules(findings)
	return driver
}

// rules deduplicates findings by rule ID into sorted SARIF rule
// descriptors. Rule-level metadata comes from the most severe finding of
// each rule so that consumers reading only rule properties (like
// bb-insights) see the right severity.
func rules(findings []report.Finding) []*sarif.ReportingDescriptor {
	byID := make(map[string]report.Finding)
	for _, f := range findings {
		best, seen := byID[f.RuleID]
		if !seen || f.Severity.Rank() > best.Severity.Rank() {
			byID[f.RuleID] = f
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]*sarif.ReportingDescriptor, 0, len(ids))
	for _, id := range ids {
		out = append(out, rule(id, byID[id]))
	}
	return out
}

func rule(id string, f report.Finding) *sarif.ReportingDescriptor {
	r := sarif.NewReportingDescriptor()
	r.ID = ptr(id)
	if f.RuleName != "" {
		r.Name = ptr(f.RuleName)
	}
	short := f.RuleName
	if short == "" {
		short = f.Title
	}
	if short != "" {
		r.ShortDescription = &sarif.MultiformatMessageString{Text: ptr(short)}
	}
	if f.Description != "" {
		r.FullDescription = &sarif.MultiformatMessageString{Text: ptr(f.Description)}
	}
	if f.URL != "" {
		r.HelpURI = ptr(f.URL)
	}

	// Tags and security-severity are what SARIF consumers use to recover
	// the real severity: SARIF level alone cannot express "critical".
	bag := sarif.NewPropertyBag()
	bag.AddTag(string(f.Category))
	if f.Severity != report.SeverityUnknown {
		bag.AddTag(strings.ToUpper(string(f.Severity)))
	}
	for _, cwe := range f.CWEs {
		bag.AddTag(cwe)
	}
	if score := securitySeverity(f); score > 0 {
		bag.Add("security-severity", score)
	}
	r.Properties = bag
	return r
}

// securitySeverity converts Aikido's 1-100 severity score onto the CVSS
// 0-10 scale used by the SARIF security-severity convention.
func securitySeverity(f report.Finding) float64 {
	if f.SeverityScore <= 0 {
		return 0
	}
	return math.Round(float64(f.SeverityScore)) / 10
}

func (g *Generator) results(findings []report.Finding) []*sarif.Result {
	// Rule index lookup must match the sorted rules array.
	ruleIndex := make(map[string]int)
	for i, r := range rules(findings) {
		ruleIndex[*r.ID] = i
	}
	out := make([]*sarif.Result, 0, len(findings))
	for _, f := range findings {
		out = append(out, result(f, ruleIndex[f.RuleID]))
	}
	return out
}

func result(f report.Finding, ruleIndex int) *sarif.Result {
	res := sarif.NewResult()
	res.RuleID = ptr(f.RuleID)
	res.RuleIndex = ruleIndex
	res.Level = level(f.Severity)
	res.Message = sarif.NewTextMessage(message(f))
	if loc := location(f); loc != nil {
		res.Locations = []*sarif.Location{loc}
	}
	res.Properties = resultProperties(f)
	return res
}

// level maps the domain severity onto the four SARIF levels. Critical
// collapses into "error"; the exact severity is preserved in rule tags and
// result properties.
func level(s report.Severity) string {
	switch s {
	case report.SeverityCritical, report.SeverityHigh:
		return "error"
	case report.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func message(f report.Finding) string {
	msg := f.Title
	if msg == "" {
		msg = f.RuleName
	}
	if msg == "" {
		msg = "Aikido finding"
	}
	if f.Description != "" {
		msg += " — " + f.Description
	}
	return msg
}

// location emits a physical location only when the finding has a real
// source file. Findings without one (typical for container image
// vulnerabilities) produce a result without locations — never an
// artificial "Dockerfile:1"-style placeholder.
func location(f report.Finding) *sarif.Location {
	if f.File == "" {
		return nil
	}
	phys := sarif.NewPhysicalLocation()
	phys.ArtifactLocation = sarif.NewSimpleArtifactLocation(f.File)
	if f.StartLine > 0 {
		region := sarif.NewRegion()
		region.StartLine = ptr(f.StartLine)
		if f.EndLine >= f.StartLine {
			region.EndLine = ptr(f.EndLine)
		}
		phys.Region = region
	}
	return sarif.NewLocationWithPhysicalLocation(phys)
}

func resultProperties(f report.Finding) *sarif.PropertyBag {
	bag := sarif.NewPropertyBag()
	add := func(key, value string) {
		if value != "" {
			bag.Add(key, value)
		}
	}
	add("aikidoIssueId", f.ID)
	add("aikidoIssueGroupId", f.GroupID)
	add("aikidoType", f.AikidoType)
	add("category", string(f.Category))
	add("severity", string(f.Severity))
	add("cve", f.CVE)
	add("cwe", strings.Join(f.CWEs, ","))
	add("packageName", f.PackageName)
	add("installedVersion", f.InstalledVersion)
	add("fixedVersions", strings.Join(f.PatchedVersions, ","))
	add("language", f.Language)
	add("exploitability", f.Exploitability)
	add("url", f.URL)

	// Extra non-standard metadata; sorted-by-key marshaling keeps this
	// deterministic.
	for k, v := range f.Properties {
		add(k, v)
	}
	return bag
}

func runProperties(t report.Target) *sarif.PropertyBag {
	bag := sarif.NewPropertyBag()
	bag.Add("targetKind", string(t.Kind))
	add := func(key, value string) {
		if value != "" {
			bag.Add(key, value)
		}
	}
	add("targetName", t.Name)
	add("registry", t.Registry)
	add("image", t.Image)
	add("tag", t.Tag)
	add("repository", t.Repository)
	add("branch", t.Branch)
	add("commit", t.Commit)
	add("aikidoReportUrl", t.ReportURL)
	return bag
}

// versionControl records repository provenance for code targets.
func versionControl(t report.Target) *sarif.VersionControlDetails {
	if t.Kind != report.TargetRepository || t.ReportURL == "" {
		return nil
	}
	vcs := sarif.NewVersionControlDetails()
	vcs.RepositoryURI = ptr(t.ReportURL)
	if t.Branch != "" {
		vcs.Branch = ptr(t.Branch)
	}
	if t.Commit != "" {
		vcs.RevisionID = ptr(t.Commit)
	}
	return vcs
}

func ptr[T any](v T) *T { return &v }
