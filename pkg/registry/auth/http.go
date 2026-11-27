package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

// StatusError deliberately omits response bodies, URLs and challenge headers.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("registry HTTP status %d", e.Code) }

func newHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	var pool *x509.CertPool
	if caFile != "" {
		file, err := os.Open(caFile)
		if err != nil {
			return nil, errors.New("could not open registry CA file")
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxResponseBytes+1))
		if err != nil || len(data) > maxResponseBytes {
			return nil, errors.New("could not read bounded registry CA file")
		}
		pool, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("could not load system registry trust roots")
		}
		count := 0
		for data = bytes.TrimSpace(data); len(data) > 0; data = bytes.TrimSpace(data) {
			if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, errors.New("invalid registry CA PEM")
			}
			// Decode exactly the first block. pem.Decode on the entire bundle
			// can silently skip a malformed block and accept a later valid one.
			endMarker := []byte("-----END CERTIFICATE-----")
			end := bytes.Index(data, endMarker)
			if end < 0 {
				return nil, errors.New("invalid registry CA PEM")
			}
			end += len(endMarker)
			block, rest := pem.Decode(data[:end])
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || bytes.Count(data[:end], []byte("-----BEGIN")) != 1 {
				return nil, errors.New("invalid registry CA PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
				return nil, errors.New("invalid registry CA certificate")
			}
			pool.AddCert(cert)
			count++
			data = data[end:]
		}
		if count == 0 {
			return nil, errors.New("registry CA file is empty")
		}
	}
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 100, MaxIdleConnsPerHost: 10, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: timeout, ExpectContinueTimeout: time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("registry redirect limit exceeded")
		}
		if _, err := secureURL(req.URL.String()); err != nil {
			return err
		}
		// Disallow even subdomain and port changes. No credentials cross origins.
		if len(via) == 0 || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			return errors.New("cross-origin registry redirect rejected")
		}
		return nil
	}}, nil
}

// Do performs a bounded HTTPS request using the same immutable transport for
// challenge, token and manifest requests. Redirects stay on the original origin.
// The caller owns and must close the returned response body.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c == nil || c.http == nil || ctx == nil || req == nil || req.URL == nil {
		return nil, errors.New("invalid registry request")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := secureURL(req.URL.String()); err != nil {
		return nil, err
	}
	response, err := c.http.Do(req.Clone(ctx))
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// http errors may embed complete sensitive URLs. Never expose those.
		return nil, errors.New("registry HTTPS request failed")
	}
	return response, nil
}

func boundedBody(ctx context.Context, response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, errors.New("could not read registry response")
	}
	if len(data) > maxResponseBytes {
		return nil, errors.New("registry response exceeds size limit")
	}
	return data, nil
}
