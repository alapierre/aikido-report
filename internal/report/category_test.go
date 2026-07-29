package report

import "testing"

func TestCategoryFromAikidoType(t *testing.T) {
	tests := []struct {
		in   string
		want Category
	}{
		{"open_source", CategorySCA},
		{"app_level_open_source", CategorySCA},
		{"docker_container", CategorySCA},
		{"sast", CategorySAST},
		{"leaked_secret", CategorySecret},
		{"iac", CategoryIaC},
		{"cloud", CategoryCloud},
		{"malware", CategoryMalware},
		{"license", CategoryLicense},
		{"eol", CategoryEOL},
		{"mobile", CategoryMobile},
		// Types without a dedicated category must survive as unknown,
		// not be dropped or mapped arbitrarily.
		{"scm_security", CategoryUnknown},
		{"ai_pentest", CategoryUnknown},
		{"surface_monitoring", CategoryUnknown},
		{"", CategoryUnknown},
		{"some_future_type", CategoryUnknown},
	}
	for _, tt := range tests {
		if got := CategoryFromAikidoType(tt.in); got != tt.want {
			t.Errorf("CategoryFromAikidoType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
