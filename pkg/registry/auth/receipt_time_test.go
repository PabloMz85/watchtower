package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	ref "github.com/distribution/reference"
)

func TestTokenLifetimeUsesResponseReceiptTime(t *testing.T) {
	for _, test := range []struct {
		name     string
		issuedAt bool
	}{
		{name: "issued_during_request", issuedAt: true},
		{name: "omitted_issue_time"},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := registrytest.NewClock()
			token := registrytest.Random(t)
			var calls atomic.Int64
			server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				// Advance virtual time only: no sleeps or real slow requests.
				clock.Advance(20 * time.Second)
				response := map[string]any{"token": token}
				if test.issuedAt {
					response["issued_at"] = clock.Now().Format(time.RFC3339Nano)
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Error(err)
				}
			}))
			client, err := auth.NewClient(auth.ClientOptions{Clock: clock, CAFile: ca})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			image, err := ref.ParseNormalizedNamed("example.test/team/image:latest")
			if err != nil {
				t.Fatal(err)
			}
			challenge := `Bearer realm="` + server.URL + `/token",service="Registry"`
			if _, err := client.GetBearerHeader(context.Background(), challenge, image, ""); err != nil {
				t.Fatalf("token issued during the request was rejected: %v", err)
			}
			// Default lifetime is 60 seconds, less the five-second safety margin.
			clock.Advance(54 * time.Second)
			if _, err := client.GetBearerHeader(context.Background(), challenge, image, ""); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatal("valid token expired relative to request start instead of response receipt")
			}
		})
	}
}
