package digest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/PabloMz85/watchtower/internal/meta"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	"github.com/PabloMz85/watchtower/pkg/registry/manifest"
	"github.com/PabloMz85/watchtower/pkg/types"
)

// ContentDigestHeader contains the registry manifest digest.
const ContentDigestHeader = "Docker-Content-Digest"

// Client uses one auth provider for challenge, token and manifest TLS requests.
type Client struct{ auth *auth.Client }

func NewClient(provider *auth.Client) (*Client, error) {
	if provider == nil {
		return nil, errors.New("registry auth client is required")
	}
	return &Client{auth: provider}, nil
}

// CompareDigest is a compatibility wrapper with secure defaults. The application
// uses an instance Client so token reuse spans containers and update sessions.
func CompareDigest(container types.Container, registryAuth string) (bool, error) {
	provider, err := auth.NewClient(auth.ClientOptions{})
	if err != nil {
		return false, err
	}
	defer provider.Close()
	client, err := NewClient(provider)
	if err != nil {
		return false, err
	}
	return client.CompareDigest(context.Background(), container, registryAuth)
}

func (c *Client) CompareDigest(ctx context.Context, container types.Container, registryAuth string) (bool, error) {
	if c == nil || c.auth == nil || ctx == nil {
		return false, errors.New("registry client and context are required")
	}
	if container == nil || (reflect.ValueOf(container).Kind() == reflect.Ptr && reflect.ValueOf(container).IsNil()) || !container.HasImageInfo() || container.ImageInfo() == nil {
		return false, errors.New("container image info missing")
	}
	registryAuth = TransformAuth(registryAuth)
	endpoint, err := manifest.BuildManifestURL(container)
	if err != nil {
		return false, errors.New("invalid registry manifest reference")
	}
	token, err := c.auth.GetAuthorization(ctx, container, registryAuth)
	if err != nil {
		return false, err
	}
	remote, err := c.GetDigest(ctx, endpoint, token.Header)
	if err != nil {
		var status *auth.StatusError
		if errors.As(err, &status) && (status.Code == 401 || status.Code == 403) {
			if invalidateErr := c.auth.InvalidateAuthorization(ctx, token); invalidateErr != nil {
				return false, invalidateErr
			}
		}
		// Do not automatically retry authorization failures. The next attempt obtains
		// a fresh token; the normal Docker pull fallback remains unchanged.
		return false, err
	}
	for _, local := range container.ImageInfo().RepoDigests {
		_, value, ok := strings.Cut(local, "@")
		if ok && value == remote {
			return true, nil
		}
	}
	return false, nil
}

// TransformAuth converts Docker's base64-encoded JSON credentials to Basic auth.
func TransformAuth(registryAuth string) string {
	b, err := base64.URLEncoding.DecodeString(registryAuth)
	if err != nil {
		b, _ = base64.StdEncoding.DecodeString(registryAuth)
	}
	credentials := &types.RegistryCredentials{}
	_ = json.Unmarshal(b, credentials)
	if credentials.Username != "" && credentials.Password != "" {
		registryAuth = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", credentials.Username, credentials.Password)))
	}
	return registryAuth
}

// GetDigest preserves the historical signature with strict system TLS trust.
func GetDigest(endpoint, token string) (string, error) {
	provider, err := auth.NewClient(auth.ClientOptions{})
	if err != nil {
		return "", err
	}
	defer provider.Close()
	client, err := NewClient(provider)
	if err != nil {
		return "", err
	}
	return client.GetDigest(context.Background(), endpoint, token)
}

// GetDigest performs a bounded HEAD request without exposing response headers or
// bodies in errors. Credentials are sent only over validated HTTPS endpoints.
func (c *Client) GetDigest(ctx context.Context, endpoint, token string) (string, error) {
	if c == nil || c.auth == nil || ctx == nil {
		return "", errors.New("registry client and context are required")
	}
	if token == "" || len(token) > 32768 || strings.ContainsAny(token, "\r\n\x00") {
		return "", errors.New("could not fetch valid registry token")
	}
	req, err := http.NewRequest(http.MethodHead, endpoint, nil)
	if err != nil {
		return "", errors.New("invalid registry manifest endpoint")
	}
	req.Header.Set("User-Agent", meta.UserAgent)
	req.Header.Set("Authorization", token)
	for _, accept := range []string{"application/vnd.docker.distribution.manifest.v2+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v1+json", "application/vnd.oci.image.index.v1+json"} {
		req.Header.Add("Accept", accept)
	}
	response, err := c.auth.Do(ctx, req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", &auth.StatusError{Code: response.StatusCode}
	}
	value := response.Header.Get(ContentDigestHeader)
	if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("registry manifest digest is missing or invalid")
	}
	return value, nil
}
