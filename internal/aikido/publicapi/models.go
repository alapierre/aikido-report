package publicapi

import (
	"encoding/json"
	"fmt"
	"strings"
)

// The structs below are transport models mirroring documented Aikido
// public API responses (see testdata/api for captured shapes). Enum-like
// fields are kept as strings on purpose: the published OpenAPI examples
// are known to disagree with the schema in places, and this tool must not
// fail on values it does not chart.

// Container is one Aikido container repository.
type Container struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	// RegistryName is the registry host as known to Aikido, e.g.
	// "registry.example.com"; empty when not applicable.
	RegistryName string `json:"registry_name"`
	// TagFilter is the repository's configured tag filter ("tag" in the
	// API); empty means the latest image is scanned.
	TagFilter string `json:"tag"`
	// LastScannedTag is the tag used by the most recent scan.
	LastScannedTag string `json:"last_scanned_tag"`
	// LastScannedAt is a unix timestamp; -1 means never scanned.
	LastScannedAt int64 `json:"last_scanned_at"`
	IsEmpty       bool  `json:"is_empty"`
	IsActive      bool  `json:"is_active"`
}

// CodeRepo is one Aikido code repository.
type CodeRepo struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Provider       string `json:"provider"`
	ExternalRepoID string `json:"external_repo_id"`
	URL            string `json:"url"`
	// Branch is the branch Aikido is configured to scan.
	Branch string `json:"branch"`
	// LastScannedAt is a unix timestamp; -1 means never scanned.
	LastScannedAt int64 `json:"last_scanned_at"`
	Active        bool  `json:"active"`
}

// Issue is one row of GET /api/public/v1/issues/export?format=json.
type Issue struct {
	ID      int    `json:"id"`
	GroupID int    `json:"group_id"`
	Type    string `json:"type"`
	// AttackSurface is Aikido's classification of where the issue applies
	// (e.g. "docker_container", "backend", "cloud"). Kept as a raw string —
	// same rationale as Type: the taxonomy is not fully documented.
	AttackSurface       string   `json:"attack_surface"`
	Rule                string   `json:"rule"`
	RuleID              string   `json:"rule_id"`
	Severity            string   `json:"severity"`
	SeverityScore       int      `json:"severity_score"`
	Status              string   `json:"status"`
	AffectedPackage     string   `json:"affected_package"`
	AffectedFile        string   `json:"affected_file"`
	CVEID               string   `json:"cve_id"`
	CWEClasses          []string `json:"cwe_classes"`
	StartLine           int      `json:"start_line"`
	EndLine             int      `json:"end_line"`
	InstalledVersion    string   `json:"installed_version"`
	PatchedVersions     []string `json:"patched_versions"`
	ProgrammingLanguage string   `json:"programming_language"`
	Exploitability      string   `json:"exploitability"`
	ContainerRepoID     int      `json:"container_repo_id"`
	ContainerRepoName   string   `json:"container_repo_name"`
	CodeRepoID          int      `json:"code_repo_id"`
	CodeRepoName        string   `json:"code_repo_name"`
}

// decodeList decodes a JSON list that the documentation specifies as a
// bare array, while also tolerating the enveloped variants ({"data": []},
// {"items": []}, ...) that have been observed from this API in the past.
// All envelope handling is contained here.
func decodeList[T any](data []byte, envelopeKeys ...string) ([]T, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var items []T
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, fmt.Errorf("decoding list: %w", err)
		}
		return items, nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decoding list envelope: %w", err)
	}
	for _, key := range envelopeKeys {
		raw, ok := envelope[key]
		if !ok {
			continue
		}
		var items []T
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("decoding list under %q: %w", key, err)
		}
		return items, nil
	}
	return nil, fmt.Errorf("unexpected list response shape (no %s key)", strings.Join(envelopeKeys, "/"))
}
