package publicapi

import (
	"testing"
)

func TestDecodeListBareArray(t *testing.T) {
	items, err := decodeList[Container]([]byte(`[{"id":1,"name":"a"},{"id":2,"name":"b"}]`), "data")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != 1 || items[1].Name != "b" {
		t.Errorf("unexpected items: %+v", items)
	}
}

func TestDecodeListEnvelopes(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
	}{
		{"data", `{"data":[{"id":3,"name":"c"}]}`},
		{"items", `{"items":[{"id":3,"name":"c"}]}`},
		{"containers", `{"containers":[{"id":3,"name":"c"}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			items, err := decodeList[Container]([]byte(tt.body), "containers", "data", "items")
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != 1 || items[0].ID != 3 {
				t.Errorf("unexpected items: %+v", items)
			}
		})
	}
}

func TestDecodeListUnknownEnvelope(t *testing.T) {
	if _, err := decodeList[Container]([]byte(`{"results":[]}`), "data", "items"); err == nil {
		t.Fatal("expected error for unknown envelope key")
	}
}

func TestDecodeListMalformed(t *testing.T) {
	for _, body := range []string{`[{"id":`, `{"data":{"x":1}}`, `42`} {
		if _, err := decodeList[Container]([]byte(body), "data"); err == nil {
			t.Errorf("expected error for %q", body)
		}
	}
}

func TestDecodeListEmptyBody(t *testing.T) {
	items, err := decodeList[Container](nil, "data")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("expected no items, got %+v", items)
	}
}

func TestIssueNullFieldsDecodeToZeroValues(t *testing.T) {
	body := []byte(`[{"id":1,"group_id":2,"type":"open_source","severity":"high",
		"affected_package":null,"affected_file":null,"cve_id":null,
		"start_line":null,"end_line":null,"installed_version":null,
		"patched_versions":[],"programming_language":null,"exploitability":null,
		"container_repo_id":101,"code_repo_id":null}]`)
	issues, err := decodeList[Issue](body, "issues")
	if err != nil {
		t.Fatal(err)
	}
	issue := issues[0]
	if issue.AffectedFile != "" || issue.CVEID != "" || issue.StartLine != 0 || issue.CodeRepoID != 0 {
		t.Errorf("null fields not zero: %+v", issue)
	}
	if issue.ContainerRepoID != 101 {
		t.Errorf("ContainerRepoID = %d", issue.ContainerRepoID)
	}
}
