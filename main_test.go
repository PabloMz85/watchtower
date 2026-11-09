package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestInitialLoggingLevel(t *testing.T) {
	if got := log.GetLevel(); got != log.InfoLevel {
		t.Fatalf("initial log level = %v, want info", got)
	}
}

func TestWatchtowerMainProcess(t *testing.T) {
	if os.Getenv("WATCHTOWER_TEST_MAIN_PROCESS") != "1" {
		t.Skip("entrypoint helper runs only in an isolated subprocess")
	}
	var arguments []string
	if err := json.Unmarshal([]byte(os.Getenv("WATCHTOWER_TEST_MAIN_ARGS")), &arguments); err != nil || len(arguments) == 0 {
		t.Fatal("invalid entrypoint test arguments")
	}
	os.Args = append([]string{"watchtower"}, arguments...)
	main()
}

func TestMainEntrypoint(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{name: "help without Docker", args: []string{"--help"}, want: []string{"Usage:", "watchtower", "--run-once"}},
		{name: "unknown flag fails", args: []string{"--not-a-watchtower-option"}, code: 1, want: []string{"unknown flag", "--not-a-watchtower-option"}},
		{name: "obsolete API rejected before connecting", args: []string{"--run-once", "--api-version", "1.25"}, code: 1, want: []string{"1.25", "1.40"}},
		{name: "negative timeout rejected", args: []string{"--run-once", "--stop-timeout=-1s"}, code: 1, want: []string{"positive value for timeout"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arguments, err := json.Marshal(tc.args)
			if err != nil {
				t.Fatalf("encode arguments: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWatchtowerMainProcess$")
			// Share runtime counters even when the CLI exits before test teardown.
			coverageDirectory := ""
			if coverage := flag.Lookup("test.gocoverdir"); testing.CoverMode() != "" && coverage != nil && coverage.Value.String() != "" {
				coverageDirectory = coverage.Value.String()
				command.Args = append(command.Args, "-test.gocoverdir", coverageDirectory)
			}
			// Never inherit notification credentials, Docker settings or user configuration.
			for _, name := range []string{"PATH", "SystemRoot", "SYSTEMROOT", "TMPDIR", "TMP", "TEMP"} {
				if value, exists := os.LookupEnv(name); exists {
					command.Env = append(command.Env, fmt.Sprintf("%s=%s", name, value))
				}
			}
			if coverageDirectory != "" {
				command.Env = append(command.Env, fmt.Sprintf("GOCOVERDIR=%s", coverageDirectory))
			}
			home := t.TempDir()
			command.Env = append(command.Env,
				fmt.Sprintf("HOME=%s", home),
				fmt.Sprintf("USERPROFILE=%s", home),
				fmt.Sprintf("DOCKER_HOST=unix://%s", filepath.Join(home, "missing-docker.sock")),
				"WATCHTOWER_TEST_MAIN_PROCESS=1",
				fmt.Sprintf("WATCHTOWER_TEST_MAIN_ARGS=%s", arguments),
			)
			output, runErr := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("entrypoint exceeded deadline: %v\n%s", ctx.Err(), output)
			}
			code := 0
			if runErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) {
					t.Fatalf("start entrypoint: %v", runErr)
				}
				code = exitErr.ExitCode()
			}
			if code != tc.code {
				t.Fatalf("exit = %d, want %d\n%s", code, tc.code, output)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(output), want) {
					t.Errorf("entrypoint output lacks %q:\n%s", want, output)
				}
			}
			if strings.Contains(string(output), "panic:") {
				t.Fatalf("entrypoint panicked:\n%s", output)
			}
		})
	}
}
