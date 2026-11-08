package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type inspectedContainer struct {
	ID     string
	Image  string
	Config struct {
		Env    []string
		Labels map[string]string
	}
	State           struct{ Running bool }
	HostConfig      struct{ RestartPolicy struct{ Name string } }
	NetworkSettings struct {
		Networks map[string]struct{ Aliases []string }
	}
}

// TestDockerUpdate exercises only disposable resources bearing a unique scope.
// It is opt-in because it requires Docker and builds fixture images.
func TestDockerUpdate(t *testing.T) {
	if os.Getenv("WATCHTOWER_INTEGRATION") != "1" {
		t.Skip("set WATCHTOWER_INTEGRATION=1 to test a real Docker update")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	scope := "watchtower-smoke-" + hex.EncodeToString(nonce[:])
	image, name, network := scope+":current", scope+"-target", scope+"-network"
	work := t.TempDir()
	binary := filepath.Join(work, "watchtower")
	run(t, ctx, nil, "go", "build", "-o", binary, "..")
	endpoint := strings.TrimSpace(run(t, ctx, nil, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"))
	if configured := os.Getenv("DOCKER_HOST"); configured != "" {
		endpoint = configured
	}
	if endpoint == "" {
		t.Fatal("Docker endpoint is empty")
	}

	// Cleanup verifies ownership before removing the named test container.
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		inspect, err := exec.CommandContext(cleanupCtx, "docker", "inspect", "--format", `{{index .Config.Labels "com.centurylinklabs.watchtower.scope"}}`, name).CombinedOutput()
		if err == nil {
			if strings.TrimSpace(string(inspect)) != scope {
				t.Errorf("refusing cleanup of container with unexpected scope: %s", name)
				return
			}
			run(t, cleanupCtx, nil, "docker", "stop", "--timeout", "2", name)
			run(t, cleanupCtx, nil, "docker", "rm", name)
		} else {
			t.Logf("test container unavailable during cleanup: %s", inspect)
		}
		run(t, cleanupCtx, nil, "docker", "network", "rm", network)
		run(t, cleanupCtx, nil, "docker", "image", "rm", image, scope+":initial")
	})

	run(t, ctx, nil, "docker", "network", "create", "--label", "watchtower.test.scope="+scope, network)
	buildFixture := func(version string) {
		t.Helper()
		dockerfile := fmt.Sprintf("FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a\nLABEL fixture.version=%q\nCMD [\"sleep\",\"3600\"]\n", version)
		if err := os.WriteFile(filepath.Join(work, "Dockerfile"), []byte(dockerfile), 0600); err != nil {
			t.Fatal(err)
		}
		run(t, ctx, nil, "docker", "build", "-t", image, work)
	}
	buildFixture("v1")
	run(t, ctx, nil, "docker", "tag", image, scope+":initial")
	run(t, ctx, nil, "docker", "run", "-d", "--name", name,
		"--network", network, "--network-alias", "service-alias", "--restart", "unless-stopped",
		"--env", "FIXTURE_SETTING=preserved", "--label", "fixture.setting=preserved",
		"--label", "com.centurylinklabs.watchtower.scope="+scope, image)
	inspect := func() inspectedContainer {
		t.Helper()
		var containers []inspectedContainer
		if err := json.Unmarshal([]byte(run(t, ctx, nil, "docker", "inspect", name)), &containers); err != nil || len(containers) != 1 {
			t.Fatalf("invalid container inspection: %v", err)
		}
		return containers[0]
	}
	before := inspect()
	buildFixture("v2")
	var environment []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "DOCKER_") && !strings.HasPrefix(entry, "WATCHTOWER_") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "DOCKER_HOST="+endpoint)
	for _, key := range []string{"DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"} {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	output := run(t, ctx, environment, binary, "--run-once", "--no-pull", "--scope", scope, name)
	after := inspect()
	if after.ID == before.ID || after.Image == before.Image || !after.State.Running || after.Config.Labels["fixture.version"] != "v2" {
		t.Fatalf("container was not updated and restarted: %s", output)
	}
	if after.Config.Labels["fixture.setting"] != "preserved" || after.HostConfig.RestartPolicy.Name != "unless-stopped" || !contains(after.Config.Env, "FIXTURE_SETTING=preserved") || !contains(after.NetworkSettings.Networks[network].Aliases, "service-alias") {
		t.Fatal("container configuration was not preserved")
	}
	if !strings.Contains(output, "Updated=1") || !strings.Contains(output, "Failed=0") {
		t.Fatalf("update did not report success: %s", output)
	}
	second := run(t, ctx, environment, binary, "--run-once", "--no-pull", "--scope", scope, name)
	if inspect().ID != after.ID || !strings.Contains(second, "Updated=0") {
		t.Fatalf("an unchanged container was unexpectedly recreated: %s", second)
	}
	t.Log("PASS: real Docker update, configuration preservation, and unchanged-image scan")
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func run(t *testing.T, ctx context.Context, environment []string, executable string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, executable, arguments...)
	if environment != nil {
		command.Env = environment
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", executable, arguments, err, output)
	}
	return string(output)
}
