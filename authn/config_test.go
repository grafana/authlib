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

	err := fs.Parse([]string{"-test.allowed-audiences", "a,b,c", "-test.disable-typ-header-check", "true"})
	require.NoError(t, err)
	require.Equal(t, jwt.Audience{"a", "b", "c"}, cfg.AllowedAudiences)
	require.True(t, cfg.DisableTypHeaderCheck)
}

func TestKeyRetrieverConfig_RegisterFlags(t *testing.T) {
	var cfg KeyRetrieverConfig
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg.RegisterFlags("test", fs)

	err := fs.Parse([]string{"-test.signing-keys-url", "http://127.0.0.1/keys"})
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1/keys", cfg.SigningKeysURL)
}

func TestTokenExchangeConfig_RegisterFlags(t *testing.T) {
	var cfg TokenExchangeConfig
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg.RegisterFlags("test", fs)

	err := fs.Parse([]string{"-test.token", "my-token", "-test.token-exchange-url", "http://127.0.0.1/token"})
	require.NoError(t, err)
	require.Equal(t, "my-token", cfg.Token)
	require.Equal(t, "http://127.0.0.1/token", cfg.TokenExchangeURL)
}
