// Package imageref parses container image references into the parts this
// tool matches against Aikido container repositories: an optional registry
// host, the repository path, and a tag.
//
// Validation is delegated to github.com/distribution/reference (the
// canonical Docker/OCI grammar), but Docker Hub normalization is
// intentionally NOT applied to the repository path: Aikido stores the name
// as configured, so "ubuntu" must stay "ubuntu", not become
// "library/ubuntu". The registry is only considered specified when the
// input names one explicitly.
package imageref

import (
	"errors"
	"fmt"
	"strings"

	"github.com/distribution/reference"
)

// Ref is a parsed image reference.
type Ref struct {
	// Registry is the lowercased registry host (with optional port), or
	// empty when the input did not name a registry explicitly. An empty
	// registry means "match any registry".
	Registry string
	// Path is the repository path exactly as typed, without the registry,
	// e.g. "team/application" or "ubuntu".
	Path string
	// ShortName is the last segment of Path, e.g. "application". Aikido
	// may store either the full path or just this segment as the name.
	ShortName string
	// Tag is the image tag. Always non-empty after a successful Parse.
	// Tags are matched case-sensitively, per the OCI distribution spec.
	Tag string
}

// String reassembles the reference for display.
func (r Ref) String() string {
	s := r.Path
	if r.Registry != "" {
		s = r.Registry + "/" + s
	}
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	return s
}

var errDigestUnsupported = errors.New("digest references are not supported: Aikido matches scans by tag, pass a tag instead")

// Parse parses an image reference plus an optional explicit tag flag.
// The image may itself carry a tag; when both are present they must agree.
// Exactly one tag must result, digests are rejected.
func Parse(image, explicitTag string) (Ref, error) {
	s := strings.TrimSpace(image)
	if s == "" {
		return Ref{}, errors.New("image reference is empty")
	}
	if strings.ContainsAny(s, " \t\n") {
		return Ref{}, fmt.Errorf("image reference %q contains whitespace", image)
	}
	if strings.Contains(s, "@") {
		return Ref{}, fmt.Errorf("parsing image reference %q: %w", image, errDigestUnsupported)
	}

	registry, remainder := splitRegistry(s)
	if remainder == "" {
		return Ref{}, fmt.Errorf("image reference %q has no repository path", image)
	}

	// After the registry is split off, a colon in the remainder can only
	// introduce a tag (ports belong to the registry part).
	tagInImage := ""
	if i := strings.LastIndex(remainder, ":"); i >= 0 {
		tagInImage = remainder[i+1:]
		remainder = remainder[:i]
		if tagInImage == "" {
			return Ref{}, fmt.Errorf("image reference %q has an empty tag", image)
		}
	}

	tag, err := resolveTag(tagInImage, strings.TrimSpace(explicitTag))
	if err != nil {
		return Ref{}, err
	}

	// Validate the full reference against the canonical grammar.
	check := remainder
	if registry != "" {
		check = registry + "/" + remainder
	}
	check += ":" + tag
	if _, err := reference.ParseNormalizedNamed(check); err != nil {
		return Ref{}, fmt.Errorf("invalid image reference %q: %w", image, err)
	}

	shortName := remainder
	if i := strings.LastIndex(remainder, "/"); i >= 0 {
		shortName = remainder[i+1:]
	}
	return Ref{
		Registry:  strings.ToLower(registry),
		Path:      remainder,
		ShortName: shortName,
		Tag:       tag,
	}, nil
}

// splitRegistry decides whether the first path segment is a registry host.
// Same rule Docker uses: it is a registry when it contains a dot or a
// colon, or is exactly "localhost". Plain namespaces ("team/app") are not
// registries.
func splitRegistry(s string) (registry, remainder string) {
	i := strings.Index(s, "/")
	if i < 0 {
		return "", s
	}
	first := s[:i]
	if strings.ContainsAny(first, ".:") || strings.EqualFold(first, "localhost") {
		return first, s[i+1:]
	}
	return "", s
}

func resolveTag(fromImage, fromFlag string) (string, error) {
	switch {
	case fromImage == "" && fromFlag == "":
		return "", errors.New("no tag specified: pass --tag or include it in the image reference")
	case fromImage != "" && fromFlag != "" && fromImage != fromFlag:
		return "", fmt.Errorf("conflicting tags: image reference says %q but --tag says %q", fromImage, fromFlag)
	case fromImage != "":
		return fromImage, nil
	default:
		return fromFlag, nil
	}
}
