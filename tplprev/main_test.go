//go:build !wasm

package main

import (
	"bytes"
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

	"github.com/PabloMz85/watchtower/internal/meta"
)

func TestTemplatePreviewProcess(t *testing.T) {
	if os.Getenv("WATCHTOWER_TPLPREV_TEST_HELPER") != "1" {
		t.Skip("entrypoint helper runs only in an isolated subprocess")
	}
	var arguments []string
	if err := json.Unmarshal([]byte(os.Getenv("WATCHTOWER_TPLPREV_TEST_ARGS")), &arguments); err != nil {
		t.Fatalf("decode helper arguments: %v", err)
	}
	os.Args = append([]string{"tplprev"}, arguments...)
	flag.CommandLine = flag.NewFlagSet("tplprev", flag.ExitOnError)
	main()
}

func TestTemplatePreviewCLI(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		template string
		noFile   bool
		missing  bool
		code     int
		output   string
		error    string
	}{
		{name: "missing argument", noFile: true, code: 1, error: "Missing required argument TEMPLATE"},
		{name: "missing file", missing: true, code: 1, error: "Failed to read template file"},
		{name: "literal with empty selectors", args: []string{"-states", "", "-entries", ""}, template: "rendered", output: "rendered"},
		{name: "empty template", args: []string{"-states", "", "-entries", ""}},
		{name: "independent state and log selectors", args: []string{"-states", "uk", "-entries", "wi"},
			template: "{{len .Report.Updated}}|{{len .Report.Skipped}}|{{len .Entries}}|{{(index .Entries 0).Level}}|{{(index .Entries 1).Level}}", output: "1|1|2|warning|info"},
		{name: "syntax error", template: "{{", code: 1, error: "failed to parse"},
		{name: "execution error has no partial output", template: "partial{{.MissingField}}", code: 1, error: "failed to execute template"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			arguments := append([]string(nil), tc.args...)
			if !tc.noFile {
				path := filepath.Join(directory, "notification.tmpl")
				if !tc.missing {
					if err := os.WriteFile(path, []byte(tc.template), 0o600); err != nil {
						t.Fatalf("write template: %v", err)
					}
				}
				arguments = append(arguments, path)
			}
			encoded, err := json.Marshal(arguments)
			if err != nil {
				t.Fatalf("encode arguments: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTemplatePreviewProcess$")
			coverageDirectory := ""
			if coverage := flag.Lookup("test.gocoverdir"); testing.CoverMode() != "" && coverage != nil && coverage.Value.String() != "" {
				coverageDirectory = coverage.Value.String()
				command.Args = append(command.Args, "-test.gocoverdir", coverageDirectory)
			}
			for _, name := range []string{"PATH", "SystemRoot", "SYSTEMROOT", "TMPDIR", "TMP", "TEMP"} {
				if value, exists := os.LookupEnv(name); exists {
					command.Env = append(command.Env, fmt.Sprintf("%s=%s", name, value))
				}
			}
			if coverageDirectory != "" {
				command.Env = append(command.Env, fmt.Sprintf("GOCOVERDIR=%s", coverageDirectory))
			}
			command.Env = append(command.Env,
				fmt.Sprintf("HOME=%s", directory),
				fmt.Sprintf("USERPROFILE=%s", directory),
				"WATCHTOWER_TPLPREV_TEST_HELPER=1",
				fmt.Sprintf("WATCHTOWER_TPLPREV_TEST_ARGS=%s", encoded),
			)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			runErr := command.Run()
			if ctx.Err() != nil {
				t.Fatalf("CLI exceeded deadline: %v\n%s", ctx.Err(), stderr.String())
			}
			code := 0
			if runErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) {
					t.Fatalf("start CLI: %v", runErr)
				}
				code = exitErr.ExitCode()
			}
			if code != tc.code {
				t.Fatalf("exit = %d, want %d\n%s", code, tc.code, stderr.String())
			}
			banner := fmt.Sprintf("watchtower/tplprev %s", meta.Version)
			if !strings.Contains(stderr.String(), banner) {
				t.Errorf("stderr lacks version banner %q: %s", banner, stderr.String())
			}
			if tc.code == 0 {
				// The first line is the CLI result; the helper runner appends PASS.
				if line, _, _ := strings.Cut(stdout.String(), "\n"); line != tc.output {
					t.Errorf("rendered output = %q, want %q", line, tc.output)
				}
			} else if stdout.Len() != 0 {
				t.Errorf("failed rendering emitted partial output: %q", stdout.String())
			}
			if tc.error != "" && !strings.Contains(stderr.String(), tc.error) {
				t.Errorf("stderr lacks %q: %s", tc.error, stderr.String())
			}
			if strings.Contains(stderr.String(), "panic:") {
				t.Fatalf("CLI panicked: %s", stderr.String())
			}
		})
	}
}
