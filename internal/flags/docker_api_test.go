package flags

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestEnvConfigRejectsInvalidAPIVersion(t *testing.T) {
	for _, version := range []string{"1.25", "1.39", "1.99", "1.40/containers", "v1.40", "1.040", " 1.40"} {
		t.Run(version, func(t *testing.T) {
			t.Setenv("DOCKER_API_VERSION", "")
			t.Setenv("DOCKER_HOST", "")
			t.Setenv("DOCKER_TLS_VERIFY", "")
			viper.Reset()
			t.Cleanup(viper.Reset)
			SetDefaults()
			cmd := new(cobra.Command)
			RegisterDockerFlags(cmd)
			require.NoError(t, cmd.ParseFlags([]string{"--api-version", version}))
			require.Error(t, EnvConfig(cmd))
			require.Empty(t, os.Getenv("DOCKER_API_VERSION"), "invalid input must not be exported")
		})
	}
}

func TestEnvConfigAPIVersion(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment string
		arguments   []string
		want        string
	}{
		{name: "automatic by default"},
		{name: "environment override", environment: "1.40", want: "1.40"},
		{name: "flag overrides environment", environment: "1.40", arguments: []string{"--api-version", "1.56"}, want: "1.56"},
		{name: "empty flag restores negotiation", environment: "1.40", arguments: []string{"--api-version="}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DOCKER_API_VERSION", test.environment)
			t.Setenv("DOCKER_HOST", "")
			t.Setenv("DOCKER_TLS_VERIFY", "")
			viper.Reset()
			t.Cleanup(viper.Reset)
			SetDefaults()
			cmd := new(cobra.Command)
			RegisterDockerFlags(cmd)
			require.NoError(t, cmd.ParseFlags(test.arguments))
			require.NoError(t, EnvConfig(cmd))
			require.Equal(t, test.want, os.Getenv("DOCKER_API_VERSION"))
		})
	}
}
