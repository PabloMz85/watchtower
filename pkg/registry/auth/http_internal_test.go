package auth

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	ref "github.com/distribution/reference"
)

type bodyRoundTripper func(*http.Request) (*http.Response, error)

func (f bodyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type cancellingBody struct {
	ctx     context.Context
	started chan struct{}
	closed  atomic.Bool
}

func (b *cancellingBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *cancellingBody) Close() error { b.closed.Store(true); return nil }

func TestCancellationAfterResponseBeforeBodyCompletes(t *testing.T) {
	c, err := NewClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &cancellingBody{ctx: ctx, started: make(chan struct{})}
	c.http = &http.Client{Transport: bodyRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header), Request: r}, nil
	})}
	image, _ := ref.ParseNormalizedNamed("example.test/image")
	done := make(chan error, 1)
	go func() {
		_, err := c.GetBearerHeader(ctx, `Bearer realm="https://example.test/token",service="Registry"`, image, "")
		done <- err
	}()
	<-body.started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("body read lost cancellation: %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("response body was not closed")
	}
}
