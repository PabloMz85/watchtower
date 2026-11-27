package auth_test

import (
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	ref "github.com/distribution/reference"
	"testing"
)

func TestChallengePreservesCaseAndRejectsUnsafeRealm(t *testing.T) {
	image, _ := ref.ParseNormalizedNamed("example.test/team/image:latest")
	u, err := auth.GetAuthURL(`Bearer realm="https://example.test/CaseSensitive?Audience=AbC",service="MixedCase"`, image)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/CaseSensitive" || u.Query().Get("service") != "MixedCase" || u.Query().Get("Audience") != "AbC" {
		t.Fatalf("challenge values changed: %v", u)
	}
	for _, realm := range []string{"http://example.test/token", "https://user:password@example.test/token", "https://example.test/token#fragment", "://bad", "https:///token"} {
		if _, err := auth.GetAuthURL(`Bearer realm="`+realm+`",service="registry"`, image); err == nil {
			t.Errorf("accepted unsafe realm %q", realm)
		}
	}
}
