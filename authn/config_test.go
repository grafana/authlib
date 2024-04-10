package authn

import (
	"flag"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestVerifierConfig_RegisterFlags(t *testing.T) {
	var cfg VerifierConfig
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg.RegisterFlags("test", fs)

	err := fs.Parse([]string{"-test.allowed-audiences", "a,b,c", "-test.signing-keys-url", "localhost"})
	require.NoError(t, err)
	require.Equal(t, jwt.Audience{"a", "b", "c"}, cfg.AllowedAudiences)
	require.Equal(t, "localhost", cfg.SigningKeysURL)
}
