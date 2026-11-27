package digest_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/registry"
	"github.com/PabloMz85/watchtower/pkg/registry/digest"
	configtypes "github.com/docker/cli/cli/config/types"
)

func TestTransformAuthAcceptsDockerURLBase64(t *testing.T) {
	username, password := registrytest.Random(t)+"\uffff", registrytest.Random(t)
	var encoded string
	for range 3 {
		var err error
		encoded, err = registry.EncodeAuth(configtypes.AuthConfig{Username: username, Password: password})
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(encoded, "-_") {
			break
		}
		username += "a"
	}
	if !strings.ContainsAny(encoded, "-_") {
		t.Fatal("fixture did not exercise URL-safe alphabet")
	}
	want := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	if got := digest.TransformAuth(encoded); got != want {
		t.Fatal("Docker URL-base64 JSON credentials were not converted to Basic auth")
	}
}
