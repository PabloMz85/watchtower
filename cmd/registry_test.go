package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistryCAFailsStartupBeforeDocker(t *testing.T) {
	for _, data := range []string{"", "not a PEM certificate"} {
		t.Run(data, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry-ca.pem")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("API-Version", "1.40")
				if r.URL.Path != "/_ping" {
					w.Write([]byte("[]"))
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
			process.Env = append(process.Env, "WATCHTOWER_TEST_RUN_ONCE=1", "DOCKER_HOST="+server.URL, "WATCHTOWER_REGISTRY_CA="+path)
			output, err := process.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("CLI timed out: %s", output)
			}
			if err == nil || !strings.Contains(string(output), "registry CA") {
				t.Fatalf("invalid registry CA did not abort startup: %v\n%s", err, output)
			}
			if requests.Load() != 0 {
				t.Fatal("Docker contacted before validating registry CA")
			}
		})
	}
}
