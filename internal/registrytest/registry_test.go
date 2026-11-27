package registrytest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/registrytest"
)

func TestCoverageFixtureRandomShapeAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for range 128 {
		value := registrytest.Random(t)
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 24 || value != strings.ToLower(value) {
			t.Fatal("random fixture must be 24 bytes encoded as lowercase hexadecimal")
		}
		if seen[value] {
			t.Fatal("random fixture repeated within the sample")
		}
		seen[value] = true
	}
}

func TestCoverageFixtureTLSCAAndCleanup(t *testing.T) {
	var endpoint, caPath string
	var trusted *http.Client
	if !t.Run("live fixture", func(t *testing.T) {
		server, path := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/fixture" || r.URL.Query().Get("check") != "trust" || r.Header.Get("X-Fixture-Request") != "present" {
				t.Error("fixture did not preserve the supplied handler's request")
			}
			if r.TLS == nil || r.TLS.Version < tls.VersionTLS12 {
				t.Error("fixture request did not use TLS 1.2 or newer")
			}
			w.Header().Set("X-Fixture-Response", "present")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, "local fixture response")
		}))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		endpoint, caPath = server.URL, path
		if server.TLS.MinVersion != tls.VersionTLS12 {
			t.Fatalf("TLS minimum = %d; want TLS 1.2", server.TLS.MinVersion)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("CA path is not a regular file: %v", info.Mode())
		}
		// Windows does not implement Unix owner/group permission bits.
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatalf("CA file permissions = %v; want mode 0600", info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			t.Fatal("CA file must contain exactly one certificate PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Fatal("fixture certificate is not a signing CA")
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			t.Fatal("fixture certificate must use an ECDSA P-256 public key")
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			t.Fatalf("fixture CA is not self-signed: %v", err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		for _, host := range []string{"localhost", "127.0.0.1"} {
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
				t.Fatalf("fixture CA does not verify for %s: %v", host, err)
			}
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
		trusted = &http.Client{Transport: transport, Timeout: 5 * time.Second}
		t.Cleanup(transport.CloseIdleConnections)
		req, err := http.NewRequest(http.MethodGet, endpoint+"/fixture?check=trust", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Fixture-Request", "present")
		response, err := trusted.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || string(body) != "local fixture response" || response.StatusCode != http.StatusCreated || response.Header.Get("X-Fixture-Response") != "present" {
			t.Fatalf("fixture response contract failed: status %d, read %v, close %v", response.StatusCode, readErr, closeErr)
		}
		untrustedTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}
		t.Cleanup(untrustedTransport.CloseIdleConnections)
		untrusted := &http.Client{Transport: untrustedTransport, Timeout: 5 * time.Second}
		if response, err := untrusted.Get(endpoint); err == nil {
			response.Body.Close()
			t.Fatal("fixture TLS was accepted without trusting its CA")
		}
	}) {
		return
	}
	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Fatalf("CA file survived fixture cleanup: %v", err)
	}
	if response, err := trusted.Get(endpoint); err == nil {
		response.Body.Close()
		t.Fatal("fixture server survived testing.T cleanup")
	}
}

func TestCoverageFixtureClockInstanceAndConcurrentAdvance(t *testing.T) {
	clock, independent := registrytest.NewClock(), registrytest.NewClock()
	start := clock.Now()
	if start.IsZero() || !start.Equal(clock.Now()) || !start.Equal(independent.Now()) {
		t.Fatal("new fixture clocks must start at the same stable nonzero instant")
	}
	clock.Advance(2 * time.Second)
	clock.Advance(-time.Second)
	if !clock.Now().Equal(start.Add(time.Second)) || !independent.Now().Equal(start) {
		t.Fatal("advancing one fixture clock did not preserve instance isolation")
	}
	const workers, iterations = 16, 100
	var group sync.WaitGroup
	ready := make(chan struct{})
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-ready
			previous := clock.Now()
			for range iterations {
				clock.Advance(time.Millisecond)
				now := clock.Now()
				if now.Before(previous) {
					t.Error("concurrent positive advances moved clock backward")
				}
				previous = now
			}
		}()
	}
	close(ready)
	group.Wait()
	want := start.Add(time.Second + workers*iterations*time.Millisecond)
	if !clock.Now().Equal(want) || !independent.Now().Equal(start) {
		t.Fatal("concurrent advances lost updates or changed another clock")
	}
}
