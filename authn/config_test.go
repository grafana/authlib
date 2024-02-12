package authn

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIDVerifierConfig_RegisterFlags(t *testing.T) {
	var cfg IDVerifierConfig
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg.RegisterFlags("test", fs)

	err := fs.Parse([]string{"-test.allowed-audiences", "a,b,c", "-test.signing-keys-url", "localhost"})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, cfg.AllowedAudiences)
	require.Equal(t, "localhost", cfg.SigningKeyURL)
}
