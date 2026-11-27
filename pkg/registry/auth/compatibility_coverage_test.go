package auth

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/types"
	ref "github.com/distribution/reference"
)

type coverageHTTPNamed string

func (n coverageHTTPNamed) Name() string   { return string(n) }
func (n coverageHTTPNamed) String() string { return string(n) }

type coverageHTTPContainer struct {
	types.Container
	image string
}

func (c coverageHTTPContainer) ImageName() string { return c.image }

func TestCoverageHTTPLegacyWrappersRejectInvalidInputs(t *testing.T) {
	// Invalid inputs exercise the public wrappers without registry or Docker I/O.
	for _, test := range []struct {
		name      string
		container types.Container
		want      string
	}{
		{"nil_container", nil, "container is required"},
		{"invalid_image", coverageHTTPContainer{image: "invalid image"}, "invalid registry image reference"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := GetToken(test.container, "")
			if err == nil || err.Error() != test.want || got != "" {
				t.Fatalf("GetToken returned %q, %v; want empty header, %q", got, err, test.want)
			}
		})
	}
	image, err := ref.ParseNormalizedNamed("example.test/team/image:latest")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, challenge string
		image           ref.Named
		want            string
	}{
		{"nil_image", `Bearer realm="https://example.test/token",service="Registry"`, nil, "image reference is required"},
		{"malformed_challenge", `Basic realm="private"`, image, "unsupported registry challenge"},
		{"insecure_realm", `Bearer realm="http://example.test/token",service="Registry"`, image, "registry endpoint must be an absolute HTTPS URL without userinfo or fragment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := GetBearerHeader(test.challenge, test.image, "")
			if err == nil || err.Error() != test.want || got != "" {
				t.Fatalf("GetBearerHeader returned %q, %v; want empty header, %q", got, err, test.want)
			}
		})
	}
}

func TestCoverageHTTPAuthURLValidationAndDerivedScope(t *testing.T) {
	image, err := ref.ParseNormalizedNamed("example.test/team/image:latest")
	if err != nil {
		t.Fatal(err)
	}
	var nilNamed *coverageHTTPNamed
	for _, test := range []struct {
		name, challenge string
		image           ref.Named
		want            string
	}{
		{"nil_image", "", nil, "image reference is required"},
		{"typed_nil_image", "", nilNamed, "image reference is required"},
		{"malformed", `Bearer service="private`, image, "unterminated registry challenge value"},
		{"duplicate", `Bearer realm="https://example.test",service="first",SERVICE="private"`, image, "duplicate registry challenge parameter"},
		{"missing_realm", `Bearer service="Registry"`, image, "registry challenge is missing realm or service"},
		{"missing_service", `Bearer realm="https://example.test"`, image, "registry challenge is missing realm or service"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := GetAuthURL(test.challenge, test.image)
			if err == nil || err.Error() != test.want || got != nil {
				t.Fatalf("GetAuthURL returned %v, %v; want nil, %q", got, err, test.want)
			}
		})
	}
	endpoint, err := GetAuthURL(`Bearer realm="https://example.test/CaseToken?Audience=AbC&scope=repository:other:push&service=wrong",service="Mixed\"Case\\Value",scope="repository:untrusted:push"`, image)
	if err != nil {
		t.Fatal(err)
	}
	wantQuery := url.Values{"Audience": {"AbC"}, "service": {"Mixed\"Case\\Value"}, "scope": {"repository:team/image:pull"}}
	if endpoint.Scheme != "https" || endpoint.Host != "example.test" || endpoint.Path != "/CaseToken" || endpoint.RawQuery != wantQuery.Encode() {
		t.Fatalf("challenge changed opaque values or trusted server scope: %v", endpoint)
	}
}

func TestCoverageHTTPChallengeURLAndRequest(t *testing.T) {
	var nilNamed *coverageHTTPNamed
	for _, image := range []ref.Named{nil, nilNamed, coverageHTTPNamed("invalid image")} {
		if got := GetChallengeURL(image); got != (url.URL{}) {
			t.Fatalf("invalid image produced challenge endpoint %v", got)
		}
	}
	endpoint := url.URL{Scheme: "https", Host: "example.test:443", Path: "/v2/", RawQuery: "Audience=AbC"}
	req, err := GetChallengeRequest(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodGet || req.URL.String() != endpoint.String() || req.Body != nil {
		t.Fatalf("unexpected challenge request: %v", req)
	}
	if req.Header.Get("Accept") != "*/*" || req.Header.Get("User-Agent") != "Watchtower (Docker)" || req.Header.Get("Authorization") != "" {
		t.Fatalf("unexpected challenge headers: %v", req.Header)
	}
	for _, endpoint := range []url.URL{
		{},
		{Scheme: "http", Host: "example.test", Path: "/v2/"},
		{Scheme: "https", Host: "example.test:0", Path: "/v2/"},
		{Scheme: "https", Host: "example.test", RawQuery: "secret=%zz"},
	} {
		if got, err := GetChallengeRequest(endpoint); err == nil || got != nil {
			t.Fatalf("unsafe endpoint produced request %v, %v", got, err)
		}
	}
}
