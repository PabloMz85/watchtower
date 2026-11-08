package cmd

import (
	"errors"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/container"
	"github.com/PabloMz85/watchtower/pkg/filters"
	"github.com/PabloMz85/watchtower/pkg/types"
	"github.com/stretchr/testify/require"
)

type scanFailureClient struct {
	container.Client
}

func (scanFailureClient) ListContainers(types.Filter) ([]types.Container, error) {
	return nil, errors.New("client version 1.25 is too old; minimum supported API version is 1.40")
}

type scanNotifier struct {
	started bool
	sent    bool
	report  types.Report
}

func (n *scanNotifier) StartNotification() { n.started = true }
func (n *scanNotifier) SendNotification(report types.Report) {
	n.sent = true
	n.report = report
}
func (*scanNotifier) AddLogHook()        {}
func (*scanNotifier) GetNames() []string { return nil }
func (*scanNotifier) GetURLs() []string  { return nil }
func (*scanNotifier) Close()             {}

func TestRunUpdatesWithNotificationsHandlesDockerFailure(t *testing.T) {
	previousClient, previousNotifier, previousHooks := client, notifier, lifecycleHooks
	t.Cleanup(func() {
		client, notifier, lifecycleHooks = previousClient, previousNotifier, previousHooks
	})
	n := &scanNotifier{}
	client, notifier, lifecycleHooks = scanFailureClient{}, n, false

	require.NotPanics(t, func() {
		require.Nil(t, runUpdatesWithNotifications(filters.NoFilter), "a failed scan must not produce success metrics")
	})
	require.True(t, n.started)
	require.True(t, n.sent, "the notification session must be completed on error")
	require.Nil(t, n.report)
}
