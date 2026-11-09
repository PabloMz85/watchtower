package types

import (
	"strings"
	"testing"
)

func TestShortID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want string
	}{
		{name: "empty"},
		{name: "short identifier", id: "0123456789a", want: "0123456789a"},
		{name: "exactly twelve characters", id: "0123456789ab", want: "0123456789ab"},
		{name: "long identifier", id: "0123456789abcdef", want: "0123456789ab"},
		{name: "sha256 prefix", id: "sha256:0123456789abcdef", want: "0123456789ab"},
		{name: "exact prefixed digest", id: "sha256:0123456789ab", want: "0123456789ab"},
		{name: "incomplete prefixed digest stays intact", id: "sha256:0123", want: "sha256:0123"},
		{name: "empty prefixed digest stays intact", id: "sha256:", want: "sha256:"},
		{name: "other algorithm keeps its prefix", id: "sha512:0123456789abcdef", want: "sha512:0123456789ab"},
		{name: "short other algorithm stays intact", id: "sha512:0123", want: "sha512:0123"},
		{name: "unrecognized prefix stays intact", id: "SHA256:0123456789abcdef", want: "SHA256:0123456789ab"},
		{name: "empty algorithm", id: ":0123456789abcdef", want: ":0123456789ab"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ImageID(tc.id).ShortID(); got != tc.want {
				t.Errorf("image ShortID(%q) = %q, want %q", tc.id, got, tc.want)
			}
			if got := ContainerID(tc.id).ShortID(); got != tc.want {
				t.Errorf("container ShortID(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

func FuzzShortID(f *testing.F) {
	for _, seed := range []string{"", "short", strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64), "other:0123456789abcdef", ":", "\xff:"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		image := ImageID(id).ShortID()
		container := ContainerID(id).ShortID()
		if image != container {
			t.Fatalf("image and container short IDs differ for %q", id)
		}
		if !strings.Contains(id, image) {
			t.Fatalf("short ID %q is not a substring of %q", image, id)
		}
		if len(id) > 0 && len(image) == 0 {
			t.Fatalf("nonempty identifier %q became empty", id)
		}
		if len(id) == 64 && !strings.ContainsRune(id, ':') && image != id[:12] {
			t.Fatal("an unprefixed full identifier was not shortened to its first twelve bytes")
		}
	})
}
