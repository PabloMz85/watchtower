package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/types"
)

type imageContainer struct {
	types.Container
	image string
}

func (c imageContainer) ImageName() string { return c.image }

func TestRejectedAuthorizationSurvivesRouteEvictionAndLateRejection(t *testing.T) {
	var endpoint string
	clock := registrytest.NewClock()
	var token atomic.Value
	token.Store(registrytest.Random(t))
	var calls atomic.Int64
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.Header().Set(ChallengeHeader, `Bearer realm="`+endpoint+`/token",service="Registry"`)
			w.WriteHeader(401)
			return
		}
		calls.Add(1)
		fmt.Fprintf(w, `{"token":%q}`, token.Load().(string))
	}))
	endpoint = server.URL
	c, err := NewClient(ClientOptions{CAFile: ca, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	container := imageContainer{image: strings.TrimPrefix(endpoint, "https://") + "/image:latest"}
	first, err := c.GetAuthorization(context.Background(), container, "")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate bounded route metadata evicted while a HEAD is in flight.
	clear(c.routes)
	c.lru.Init()
	if err := c.InvalidateAuthorization(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	token.Store(registrytest.Random(t))
	second, err := c.GetAuthorization(context.Background(), container, "")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || second.Header == first.Header {
		t.Fatal("evicted route prevented rejected token refresh")
	}
	if err := c.InvalidateAuthorization(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	current, err := c.GetAuthorization(context.Background(), container, "")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || current.Header != second.Header {
		t.Fatal("late rejection evicted newer token")
	}
	if err := c.InvalidateAuthorization(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetAuthorization(context.Background(), container, ""); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("current rejection did not refresh")
	}
}
