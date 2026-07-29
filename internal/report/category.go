package report

// Category is a stable, coarse classification of findings. It deliberately
// does not mirror the full Aikido issue-type taxonomy: types without a
// dedicated category map to CategoryUnknown and keep the original Aikido
// type string on the finding, so no data is lost and new upstream types
// never break the report.
type Category string

// Categories of findings this tool distinguishes.
const (
	CategorySCA     Category = "sca"     // vulnerable dependencies (application or OS packages)
	CategorySAST    Category = "sast"    // static analysis findings in first-party code
	CategorySecret  Category = "secret"  // leaked secrets
	CategoryIaC     Category = "iac"     // infrastructure-as-code misconfiguration
	CategoryCloud   Category = "cloud"   // cloud configuration issues
	CategoryMalware Category = "malware" // malicious packages
	CategoryLicense Category = "license" // license risk
	CategoryEOL     Category = "eol"     // end-of-life runtimes or dependencies
	CategoryMobile  Category = "mobile"  // mobile app findings
	CategoryUnknown Category = "unknown"
)

// aikidoTypeToCategory maps documented Aikido issue types onto categories.
// Types absent from this table (e.g. scm_security, ai_pentest,
// surface_monitoring) intentionally fall through to CategoryUnknown.
var aikidoTypeToCategory = map[string]Category{
	"open_source":           CategorySCA,
	"app_level_open_source": CategorySCA,
	"docker_container":      CategorySCA,
	"sast":                  CategorySAST,
	"leaked_secret":         CategorySecret,
	"iac":                   CategoryIaC,
	"cloud":                 CategoryCloud,
	"malware":               CategoryMalware,
	"license":               CategoryLicense,
	"eol":                   CategoryEOL,
	"mobile":                CategoryMobile,
}

// CategoryFromAikidoType maps an Aikido issue type onto a Category.
func CategoryFromAikidoType(aikidoType string) Category {
	if c, ok := aikidoTypeToCategory[aikidoType]; ok {
		return c
	}
	return CategoryUnknown
}
