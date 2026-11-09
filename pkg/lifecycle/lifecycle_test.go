package lifecycle

import (
	"errors"
	"io"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/container"
	"github.com/PabloMz85/watchtower/pkg/types"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// Embedded interfaces deliberately panic if production calls an unexpected method.
type lifecycleClient struct {
	container.Client
	get     func(types.ContainerID) (types.Container, error)
	list    func(types.Filter) ([]types.Container, error)
	execute func(types.ContainerID, string, int) (bool, error)
}

func (c lifecycleClient) GetContainer(id types.ContainerID) (types.Container, error) {
	return c.get(id)
}

func (c lifecycleClient) ListContainers(filter types.Filter) ([]types.Container, error) {
	return c.list(filter)
}

func (c lifecycleClient) ExecuteCommand(id types.ContainerID, command string, timeout int) (bool, error) {
	return c.execute(id, command, timeout)
}

func captureLifecycleLogs(t *testing.T) *logtest.Hook {
	t.Helper()
	logger := log.StandardLogger()
	oldHooks, oldOutput, oldLevel := logger.Hooks, logger.Out, logger.GetLevel()
	logger.ReplaceHooks(make(log.LevelHooks))
	logger.SetOutput(io.Discard)
	logger.SetLevel(log.DebugLevel)
	hook := logtest.NewGlobal()
	t.Cleanup(func() {
		logger.ReplaceHooks(oldHooks)
		logger.SetOutput(oldOutput)
		logger.SetLevel(oldLevel)
	})
	return hook
}

type lifecycleContainer struct {
	types.Container
	id                                         types.ContainerID
	name                                       string
	preCheck, postCheck, preUpdate, postUpdate string
	preTimeout, postTimeout                    int
	running, restarting                        bool
}

func (c lifecycleContainer) ID() types.ContainerID                 { return c.id }
func (c lifecycleContainer) Name() string                          { return c.name }
func (c lifecycleContainer) GetLifecyclePreCheckCommand() string   { return c.preCheck }
func (c lifecycleContainer) GetLifecyclePostCheckCommand() string  { return c.postCheck }
func (c lifecycleContainer) GetLifecyclePreUpdateCommand() string  { return c.preUpdate }
func (c lifecycleContainer) GetLifecyclePostUpdateCommand() string { return c.postUpdate }
func (c lifecycleContainer) PreUpdateTimeout() int                 { return c.preTimeout }
func (c lifecycleContainer) PostUpdateTimeout() int                { return c.postTimeout }
func (c lifecycleContainer) IsRunning() bool                       { return c.running }
func (c lifecycleContainer) IsRestarting() bool                    { return c.restarting }

func TestExecutePostUpdateCommandContainerLookupFailure(t *testing.T) {
	hook := captureLifecycleLogs(t)
	wantErr := errors.New("container lookup failed")
	id := types.ContainerID("sha256:0123456789abcdef")
	calls := 0
	client := lifecycleClient{get: func(got types.ContainerID) (types.Container, error) {
		calls++
		if got != id {
			t.Errorf("lookup ID = %q, want %q", got, id)
		}
		return nil, wantErr
	}}

	ExecutePostUpdateCommand(client, id)

	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls)
	}
	entry := hook.LastEntry()
	if entry == nil || entry.Level != log.ErrorLevel || entry.Message != wantErr.Error() || entry.Data["containerID"] != id.ShortID() {
		t.Fatalf("expected lookup error with short container ID, got %#v", entry)
	}
}

func TestCheckCommands(t *testing.T) {
	for _, phase := range []struct {
		name string
		run  func(container.Client, types.Container)
	}{
		{"pre", ExecutePreCheckCommand},
		{"post", ExecutePostCheckCommand},
	} {
		t.Run(phase.name, func(t *testing.T) {
			for _, scenario := range []struct {
				name, command string
				err           error
			}{
				{name: "missing command"},
				{name: "success", command: "check-hook"},
				{name: "failure is logged", command: "check-hook", err: errors.New("check failed")},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					hook := captureLifecycleLogs(t)
					c := lifecycleContainer{id: "check-id", name: "check-container", preCheck: scenario.command, postCheck: scenario.command}
					calls := 0
					client := lifecycleClient{execute: func(id types.ContainerID, command string, timeout int) (bool, error) {
						calls++
						if id != c.id || command != scenario.command || timeout != 1 {
							t.Errorf("execution = (%q, %q, %d), want (%q, %q, 1)", id, command, timeout, c.id, scenario.command)
						}
						return false, scenario.err
					}}
					phase.run(client, c)
					wantCalls := 1
					if scenario.command == "" {
						wantCalls = 0
					}
					if calls != wantCalls {
						t.Fatalf("execution calls = %d, want %d", calls, wantCalls)
					}
					entry := hook.LastEntry()
					if entry == nil || entry.Data["container"] != c.name {
						t.Fatalf("missing container log context: %#v", entry)
					}
					if scenario.err != nil && (entry.Level != log.ErrorLevel || entry.Message != scenario.err.Error()) {
						t.Fatalf("expected command error log, got %#v", entry)
					}
				})
			}
		})
	}
}

func TestExecutePreUpdateCommand(t *testing.T) {
	wantErr := errors.New("pre-update failed")
	for _, tc := range []struct {
		name, command       string
		running, restarting bool
		timeout             int
		skip                bool
		err                 error
		wantCalls           int
	}{
		{name: "missing command", running: true},
		{name: "stopped", command: "pre-hook"},
		{name: "restarting", command: "pre-hook", running: true, restarting: true},
		{name: "success forwards timeout", command: "pre-hook", running: true, timeout: 7, wantCalls: 1},
		{name: "unlimited timeout", command: "pre-hook", running: true, timeout: 0, wantCalls: 1},
		{name: "skip propagates", command: "pre-hook", running: true, timeout: 2, skip: true, wantCalls: 1},
		{name: "error propagates", command: "pre-hook", running: true, timeout: 3, err: wantErr, wantCalls: 1},
		{name: "skip and error propagate", command: "pre-hook", running: true, skip: true, err: wantErr, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captureLifecycleLogs(t)
			c := lifecycleContainer{id: "pre-id", name: "pre-container", preUpdate: tc.command, preTimeout: tc.timeout, running: tc.running, restarting: tc.restarting}
			calls := 0
			client := lifecycleClient{execute: func(id types.ContainerID, command string, timeout int) (bool, error) {
				calls++
				if id != c.id || command != tc.command || timeout != tc.timeout {
					t.Errorf("execution = (%q, %q, %d), want (%q, %q, %d)", id, command, timeout, c.id, tc.command, tc.timeout)
				}
				return tc.skip, tc.err
			}}
			skip, err := ExecutePreUpdateCommand(client, c)
			if calls != tc.wantCalls || skip != tc.skip || !errors.Is(err, tc.err) {
				t.Fatalf("calls/skip/error = (%d, %t, %v), want (%d, %t, %v)", calls, skip, err, tc.wantCalls, tc.skip, tc.err)
			}
		})
	}
}

func TestExecutePostUpdateCommand(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		timeout       int
		err           error
	}{
		{name: "missing command"},
		{name: "success forwards timeout", command: "post-hook", timeout: 9},
		{name: "unlimited timeout", command: "post-hook"},
		{name: "failure is logged", command: "post-hook", timeout: 4, err: errors.New("post-update failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := captureLifecycleLogs(t)
			id := types.ContainerID("new-container-id")
			c := lifecycleContainer{id: "different-inspected-id", name: "post-container", postUpdate: tc.command, postTimeout: tc.timeout}
			lookups, calls := 0, 0
			client := lifecycleClient{
				get: func(got types.ContainerID) (types.Container, error) {
					lookups++
					if got != id {
						t.Errorf("lookup ID = %q, want %q", got, id)
					}
					return c, nil
				},
				execute: func(got types.ContainerID, command string, timeout int) (bool, error) {
					calls++
					if got != id || command != tc.command || timeout != tc.timeout {
						t.Errorf("execution = (%q, %q, %d), want (%q, %q, %d)", got, command, timeout, id, tc.command, tc.timeout)
					}
					return false, tc.err
				},
			}
			ExecutePostUpdateCommand(client, id)
			wantCalls := 1
			if tc.command == "" {
				wantCalls = 0
			}
			if lookups != 1 || calls != wantCalls {
				t.Fatalf("lookups/executions = %d/%d, want 1/%d", lookups, calls, wantCalls)
			}
			entry := hook.LastEntry()
			if entry == nil || entry.Data["container"] != c.name {
				t.Fatalf("missing container log context: %#v", entry)
			}
			if tc.err != nil && (entry.Level != log.ErrorLevel || entry.Message != tc.err.Error()) {
				t.Fatalf("expected command error log, got %#v", entry)
			}
		})
	}
}

func TestExecuteChecksListsContainers(t *testing.T) {
	for _, phase := range []struct {
		name string
		run  func(container.Client, types.UpdateParams)
	}{
		{"pre", ExecutePreChecks},
		{"post", ExecutePostChecks},
	} {
		t.Run(phase.name, func(t *testing.T) {
			for _, scenario := range []string{"success", "empty", "list failure"} {
				t.Run(scenario, func(t *testing.T) {
					captureLifecycleLogs(t)
					containers := []types.Container{
						lifecycleContainer{id: "first", preCheck: "first-check", postCheck: "first-check"},
						lifecycleContainer{id: "missing"},
						lifecycleContainer{id: "last", preCheck: "last-check", postCheck: "last-check"},
					}
					filterCalls, lists := 0, 0
					filter := func(types.FilterableContainer) bool { filterCalls++; return true }
					var executed []types.ContainerID
					client := lifecycleClient{
						list: func(got types.Filter) ([]types.Container, error) {
							lists++
							if got == nil || !got(nil) {
								t.Error("filter not forwarded")
							}
							if scenario == "empty" {
								return nil, nil
							}
							if scenario == "list failure" {
								return containers, errors.New("list failed")
							}
							return containers, nil
						},
						execute: func(id types.ContainerID, command string, timeout int) (bool, error) {
							executed = append(executed, id)
							if command != string(id)+"-check" || timeout != 1 {
								t.Errorf("unexpected command/timeout: %q/%d", command, timeout)
							}
							return false, errors.New("continue after hook failure")
						},
					}
					phase.run(client, types.UpdateParams{Filter: filter})
					if lists != 1 || filterCalls != 1 {
						t.Fatalf("list/filter calls = %d/%d, want 1/1", lists, filterCalls)
					}
					if scenario == "success" {
						if len(executed) != 2 || executed[0] != "first" || executed[1] != "last" {
							t.Fatalf("executed = %v, want [first last]", executed)
						}
					} else if len(executed) != 0 {
						t.Fatalf("executed after %s: %v", scenario, executed)
					}
				})
			}
		})
	}
}
