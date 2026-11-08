package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunOnceHelper(t *testing.T) {
	if os.Getenv("WATCHTOWER_TEST_RUN_ONCE") != "1" {
		return
	}
	rootCmd.SetArgs([]string{"--run-once", "--monitor-only", "--no-pull", "watchtower-test-target"})
	Execute()
	os.Exit(0)
}

func TestRunOnceExitStatus(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      int
		body        string
		wantStatus  int
		apiVersion  string
		wantMessage string
	}{
		{name: "empty scan succeeds", status: http.StatusOK, body: "[]", wantStatus: 0},
		{name: "explicit compatible pin", status: http.StatusOK, body: "[]", wantStatus: 0, apiVersion: "1.40"},
		{name: "legacy pin is rejected", wantStatus: 1, apiVersion: "1.25", wantMessage: "1.25"},
		{name: "malformed pin is rejected", wantStatus: 1, apiVersion: "1.40/containers", wantMessage: "invalid API version"},
		{name: "daemon failure exits cleanly", status: http.StatusServiceUnavailable,
			body: `{"message":"daemon unavailable"}`, wantStatus: 1, wantMessage: "daemon unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					w.Header().Set("API-Version", "1.40")
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.Method != http.MethodGet || r.URL.Path != "/v1.40/containers/json" {
					t.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, err := fmt.Fprint(w, test.body)
				if err != nil {
					t.Errorf("write Docker response: %v", err)
				}
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunOnceHelper$")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "DOCKER_") && !strings.HasPrefix(entry, "WATCHTOWER_") {
					process.Env = append(process.Env, entry)
				}
			}
			process.Env = append(process.Env, "WATCHTOWER_TEST_RUN_ONCE=1", "DOCKER_HOST="+server.URL, "DOCKER_API_VERSION="+test.apiVersion)
			output, err := process.CombinedOutput()
			require.NoError(t, ctx.Err(), "CLI timed out: %s", output)
			if test.wantStatus == 0 {
				require.NoError(t, err, "%s", output)
				require.Contains(t, string(output), "Session done")
			} else {
				var exitError *exec.ExitError
				require.ErrorAs(t, err, &exitError, "%s", output)
				require.Equal(t, test.wantStatus, exitError.ExitCode(), "%s", output)
				require.Contains(t, string(output), test.wantMessage)
			}
			require.NotContains(t, string(output), "panic:")
		})
	}
}
