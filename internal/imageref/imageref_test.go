package imageref

import (
	"strings"
	"testing"
)

func TestParseValidReferences(t *testing.T) {
	tests := []struct {
		name  string
		image string
		tag   string
		want  Ref
	}{
		{"bare name", "ubuntu", "24.04",
			Ref{Registry: "", Path: "ubuntu", ShortName: "ubuntu", Tag: "24.04"}},
		{"namespaced", "library/ubuntu", "24.04",
			Ref{Registry: "", Path: "library/ubuntu", ShortName: "ubuntu", Tag: "24.04"}},
		{"docker.io explicit", "docker.io/library/ubuntu", "24.04",
			Ref{Registry: "docker.io", Path: "library/ubuntu", ShortName: "ubuntu", Tag: "24.04"}},
		{"org app", "org/application", "1.0",
			Ref{Registry: "", Path: "org/application", ShortName: "application", Tag: "1.0"}},
		{"ghcr", "ghcr.io/org/application", "1.0",
			Ref{Registry: "ghcr.io", Path: "org/application", ShortName: "application", Tag: "1.0"}},
		{"private registry", "registry.example.com/team/application", "1.2.3",
			Ref{Registry: "registry.example.com", Path: "team/application", ShortName: "application", Tag: "1.2.3"}},
		{"registry with port", "registry.example.com:5000/team/application", "1.2.3",
			Ref{Registry: "registry.example.com:5000", Path: "team/application", ShortName: "application", Tag: "1.2.3"}},
		{"tag inside image", "registry.example.com/team/application:1.2.3", "",
			Ref{Registry: "registry.example.com", Path: "team/application", ShortName: "application", Tag: "1.2.3"}},
		{"localhost", "localhost/application", "dev",
			Ref{Registry: "localhost", Path: "application", ShortName: "application", Tag: "dev"}},
		{"localhost with port", "localhost:5000/application", "dev",
			Ref{Registry: "localhost:5000", Path: "application", ShortName: "application", Tag: "dev"}},
		{"same tag in both", "app:1.2.3", "1.2.3",
			Ref{Registry: "", Path: "app", ShortName: "app", Tag: "1.2.3"}},
		{"registry host lowercased", "Registry.Example.COM/team/app", "1.0",
			Ref{Registry: "registry.example.com", Path: "team/app", ShortName: "app", Tag: "1.0"}},
		{"deep path", "registry.example.com/a/b/c", "1.0",
			Ref{Registry: "registry.example.com", Path: "a/b/c", ShortName: "c", Tag: "1.0"}},
		{"uppercase tag preserved", "app", "V1.2-RC1",
			Ref{Registry: "", Path: "app", ShortName: "app", Tag: "V1.2-RC1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.image, tt.tag)
			if err != nil {
				t.Fatalf("Parse(%q, %q): %v", tt.image, tt.tag, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q, %q) = %+v, want %+v", tt.image, tt.tag, got, tt.want)
			}
		})
	}
}

func TestParseInvalidReferences(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		tag     string
		errPart string
	}{
		{"empty image", "", "1.0", "empty"},
		{"whitespace only", "   ", "1.0", "empty"},
		{"internal whitespace", "my app", "1.0", "whitespace"},
		{"no tag anywhere", "app", "", "no tag"},
		{"empty tag in image", "app:", "", "empty tag"},
		{"conflicting tags", "app:1.0", "2.0", "conflicting"},
		{"digest", "app@sha256:1111111111111111111111111111111111111111111111111111111111111111", "1.0", "digest"},
		{"malformed digest", "app@notadigest", "1.0", "digest"},
		{"double tag", "registry.example.com/app:1:2", "", "invalid"},
		{"uppercase path", "registry.example.com/Team/App", "1.0", "invalid"},
		{"trailing slash", "registry.example.com/team/", "1.0", "invalid"},
		{"bad tag characters", "app", "not a tag", "invalid"},
		{"bad registry port", "registry.example.com:port/app", "1.0", "invalid"},
		{"only registry", "registry.example.com/", "1.0", "no repository path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.image, tt.tag)
			if err == nil {
				t.Fatalf("Parse(%q, %q) succeeded, want error containing %q", tt.image, tt.tag, tt.errPart)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.errPart) {
				t.Errorf("Parse(%q, %q) error = %q, want substring %q", tt.image, tt.tag, err, tt.errPart)
			}
		})
	}
}

func TestRefString(t *testing.T) {
	tests := []struct {
		ref  Ref
		want string
	}{
		{Ref{Registry: "ghcr.io", Path: "org/app", Tag: "1.0"}, "ghcr.io/org/app:1.0"},
		{Ref{Path: "app", Tag: "2.0"}, "app:2.0"},
		{Ref{Path: "app"}, "app"},
	}
	for _, tt := range tests {
		if got := tt.ref.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

// FuzzParse ensures the parser never panics and always returns either an
// error or a Ref with a non-empty path and tag.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"ubuntu", "library/ubuntu:24.04", "registry.example.com:5000/team/app:1.2.3",
		"localhost/app", "a@sha256:x", ":", "/", "a:", "a//b", "a b", "π/app:tag",
	}
	for _, s := range seeds {
		f.Add(s, "1.0")
		f.Add(s, "")
	}
	f.Fuzz(func(t *testing.T, image, tag string) {
		ref, err := Parse(image, tag)
		if err != nil {
			return
		}
		if ref.Path == "" || ref.ShortName == "" || ref.Tag == "" {
			t.Errorf("Parse(%q, %q) returned incomplete ref without error: %+v", image, tag, ref)
		}
	})
}
