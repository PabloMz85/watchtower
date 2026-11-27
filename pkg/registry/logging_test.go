package registry

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/sirupsen/logrus"
)

func TestCredentialsNeverAppearInRegistryLogs(t *testing.T) {
	username, password := registrytest.Random(t), registrytest.Random(t)
	logger := logrus.StandardLogger()
	out, level := logger.Out, logger.GetLevel()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(logrus.TraceLevel)
	defer func() { logger.SetOutput(out); logger.SetLevel(level) }()
	t.Setenv("REPO_USER", username)
	t.Setenv("REPO_PASS", password)
	encoded, err := EncodedEnvAuth()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{username, password, encoded, base64.StdEncoding.EncodeToString([]byte(username + ":" + password))} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("environment credentials leaked in logs")
		}
	}
	logs.Reset()
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)
	config := map[string]interface{}{"auths": map[string]interface{}{"example.test": map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(username + ":" + password))}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := EncodedConfigAuth("example.test/team/image:latest"); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{username, password, encoded} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("file credentials leaked in logs")
		}
	}
}
