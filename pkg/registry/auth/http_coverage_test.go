package auth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/registrytest"
)

type coverageHTTPRoundTripper func(*http.Request) (*http.Response, error)

func (f coverageHTTPRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type coverageHTTPBody struct {
	io.Reader
	read, closed int
}

func (b *coverageHTTPBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *coverageHTTPBody) Close() error { b.closed++; return nil }

type coverageHTTPErrorReader struct{}

func (coverageHTTPErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("private-reader-details")
}

func TestCoverageHTTPCAFileFailures(t *testing.T) {
	for _, test := range []struct{ name, data, want string }{
		{"missing", "", "could not open registry CA file"},
		{"oversize", strings.Repeat("x", maxResponseBytes+1), "could not read bounded registry CA file"},
		{"missing_end_marker", "-----BEGIN CERTIFICATE-----\nYmFk\n", "invalid registry CA PEM"},
		{"wrong_end_type", "-----BEGIN CERTIFICATE-----\nYmFk\n-----END PUBLIC KEY-----\n", "invalid registry CA PEM"},
		{"pem_headers", "-----BEGIN CERTIFICATE-----\nComment: private\n\nYmFk\n-----END CERTIFICATE-----\n", "invalid registry CA PEM"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-ca.pem")
			if test.name != "missing" {
				if err := os.WriteFile(path, []byte(test.data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := NewClient(ClientOptions{CAFile: path, Timeout: 2 * time.Second})
			if got != nil {
				got.Close()
			}
			if err == nil || err.Error() != test.want || got != nil {
				t.Fatalf("NewClient returned %v, %v; want nil, %q", got, err, test.want)
			}
		})
	}
}

func TestCoverageHTTPDoRejectsBeforeTransport(t *testing.T) {
	calls := 0
	client := &Client{http: &http.Client{Transport: coverageHTTPRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected transport dispatch")
	})}}
	defer client.Close()
	req, err := http.NewRequest(http.MethodGet, "https://example.test/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var nilContext context.Context
	for _, test := range []struct {
		name   string
		client *Client
		ctx    context.Context
		req    *http.Request
	}{
		{"nil_client", nil, context.Background(), req},
		{"zero_client", &Client{}, context.Background(), req},
		{"nil_context", client, nilContext, req},
		{"nil_request", client, context.Background(), nil},
		{"nil_url", client, context.Background(), &http.Request{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.client.Do(test.ctx, test.req)
			if err == nil || err.Error() != "invalid registry request" || got != nil {
				t.Fatalf("Do returned %v, %v; want nil, invalid registry request", got, err)
			}
		})
	}
	if got, err := client.Do(cancelled, req); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("pre-cancelled Do returned %v, %v", got, err)
	}
	for _, raw := range []string{"http://example.test/path", "https://user:private@example.test/path", "https://example.test/path#private", "https://example.test:65536/path", "https://example.test/path?secret=%zz"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := client.Do(context.Background(), &http.Request{Method: http.MethodGet, URL: u}); err == nil || got != nil {
			t.Fatalf("unsafe Do returned %v, %v", got, err)
		}
	}
	if calls != 0 {
		t.Fatalf("rejected requests reached transport %d times", calls)
	}
}

func TestCoverageHTTPDoSanitizesTransportFailure(t *testing.T) {
	for _, cancelDuringTransport := range []bool{false, true} {
		t.Run(map[bool]string{false: "sanitized", true: "cancelled"}[cancelDuringTransport], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, err := http.NewRequest(http.MethodGet, "https://example.test/PrivatePath?secret=private-query", nil)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			client := &Client{http: &http.Client{Transport: coverageHTTPRoundTripper(func(sent *http.Request) (*http.Response, error) {
				calls++
				if sent == req || sent.Context() != ctx {
					t.Error("Do did not clone request with the caller context")
				}
				if cancelDuringTransport {
					cancel()
				}
				return nil, errors.New("private-transport-details")
			})}}
			defer client.Close()
			got, err := client.Do(ctx, req)
			if got != nil || err == nil || calls != 1 {
				t.Fatalf("Do returned %v, %v after %d dispatches", got, err, calls)
			}
			if cancelDuringTransport {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("transport cancellation lost: %v", err)
				}
			} else if err.Error() != "registry HTTPS request failed" {
				t.Fatalf("transport details exposed: %v", err)
			}
			if req.Context().Err() != nil {
				t.Fatal("Do changed the original request context")
			}
		})
	}
}

func TestCoverageHTTPBoundedBodyOwnershipAndErrors(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name    string
		reader  io.Reader
		ctx     context.Context
		want    string
		wantLen int
	}{
		{"exact_limit", strings.NewReader(strings.Repeat("x", maxResponseBytes)), context.Background(), "", maxResponseBytes},
		{"over_limit", strings.NewReader(strings.Repeat("x", maxResponseBytes+100)), context.Background(), "registry response exceeds size limit", 0},
		{"reader_error", io.MultiReader(strings.NewReader("private-partial-body"), coverageHTTPErrorReader{}), context.Background(), "could not read registry response", 0},
		{"cancelled_reader_error", coverageHTTPErrorReader{}, cancelled, context.Canceled.Error(), 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &coverageHTTPBody{Reader: test.reader}
			got, err := boundedBody(test.ctx, &http.Response{Body: body})
			if body.closed != 1 || body.read > maxResponseBytes+1 {
				t.Fatalf("body ownership/bound violated: closed=%d read=%d", body.closed, body.read)
			}
			if test.want == "" {
				if err != nil || len(got) != test.wantLen || string(got) != strings.Repeat("x", test.wantLen) {
					t.Fatalf("exact-limit body returned %d bytes, %v", len(got), err)
				}
			} else if err == nil || err.Error() != test.want || got != nil {
				t.Fatalf("boundedBody returned %d bytes, %v; want nil, %q", len(got), err, test.want)
			}
			if test.ctx.Err() != nil && !errors.Is(err, test.ctx.Err()) {
				t.Fatalf("body error lost cancellation identity: %v", err)
			}
		})
	}
}

func TestCoverageHTTPDoTrustedTLSResponse(t *testing.T) {
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture:"+registrytest.Random(t)))
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/CasePath" || r.URL.RawQuery != "Audience=AbC" || r.Header.Get("Authorization") != credential {
			t.Errorf("request changed before trusted TLS handler: %s %s", r.Method, r.URL)
		}
		w.Header().Set("X-Registry-Result", "CasePreserved")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "local-registry-body")
	}))
	client, err := NewClient(ClientOptions{CAFile: ca, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/CasePath?Audience=AbC", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", credential)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := client.Do(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.TLS == nil || response.TLS.Version < tls.VersionTLS12 || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("response did not use verified TLS")
	}
	if response.StatusCode != http.StatusTeapot || response.Header.Get("X-Registry-Result") != "CasePreserved" {
		t.Fatalf("Do changed response status or headers: %v", response)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "local-registry-body" {
		t.Fatalf("caller could not read response body: %q, %v", body, err)
	}
}
