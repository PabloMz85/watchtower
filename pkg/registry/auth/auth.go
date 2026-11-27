package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/PabloMz85/watchtower/pkg/registry/helpers"
	"github.com/PabloMz85/watchtower/pkg/types"
	ref "github.com/distribution/reference"
)

// ChallengeHeader is the HTTP header containing challenge instructions.
const ChallengeHeader = "WWW-Authenticate"

// GetToken is a compatibility wrapper using a fresh secure client. Long-lived
// callers should inject a Client to reuse tokens and connections across requests.
func GetToken(container types.Container, registryAuth string) (string, error) {
	client, err := NewClient(ClientOptions{})
	if err != nil {
		return "", err
	}
	defer client.Close()
	return client.GetToken(context.Background(), container, registryAuth)
}

// GetChallengeRequest validates an HTTPS endpoint before constructing a request.
func GetChallengeRequest(endpoint url.URL) (*http.Request, error) {
	if _, err := secureURL(endpoint.String()); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("invalid registry challenge request")
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "Watchtower (Docker)")
	return req, nil
}

// GetBearerHeader preserves the historical API with secure defaults.
func GetBearerHeader(challenge string, image ref.Named, registryAuth string) (string, error) {
	client, err := NewClient(ClientOptions{})
	if err != nil {
		return "", err
	}
	defer client.Close()
	return client.GetBearerHeader(context.Background(), challenge, image, registryAuth)
}

// GetAuthURL preserves case-sensitive challenge values and derives the requested
// repository pull scope itself rather than trusting a server-supplied scope.
func GetAuthURL(challenge string, image ref.Named) (*url.URL, error) {
	if isNil(image) {
		return nil, errors.New("image reference is required")
	}
	values, err := parseChallenge(challenge)
	if err != nil {
		return nil, err
	}
	if values["realm"] == "" || values["service"] == "" {
		return nil, errors.New("registry challenge is missing realm or service")
	}
	endpoint, err := secureURL(values["realm"])
	if err != nil {
		return nil, err
	}
	q := endpoint.Query()
	q.Set("service", values["service"])
	q.Set("scope", fmt.Sprintf("repository:%s:pull", ref.Path(image)))
	endpoint.RawQuery = q.Encode()
	return endpoint, nil
}

// GetChallengeURL returns the HTTPS challenge endpoint for an image registry.
func GetChallengeURL(image ref.Named) url.URL {
	if isNil(image) {
		return url.URL{}
	}
	host, err := helpers.GetRegistryAddress(image.Name())
	if err != nil {
		return url.URL{}
	}
	return url.URL{Scheme: "https", Host: host, Path: "/v2/"}
}
