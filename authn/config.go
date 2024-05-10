package authn

import (
	"flag"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"
)

type VerifierConfig struct {
	SigningKeysURL   string       `yaml:"signingKeysUrl"`
	AllowedAudiences jwt.Audience `yaml:"allowedAudiences"`
}

func (c *VerifierConfig) RegisterFlags(prefix string, fs *flag.FlagSet) {
	fs.StringVar(&c.SigningKeysURL, prefix+".signing-keys-url", "", "URL to jwks endpoint.")

	fs.Func(prefix+".allowed-audiences", "Specifies a comma-separated list of allowed audiences.", func(v string) error {
		c.AllowedAudiences = jwt.Audience(strings.Split(v, ","))
		return nil
	})
}

type TokenExchangeConfig struct {
	// Token used to perform the exchange request.
	Token string
	// Url called to perform exchange request.
	TokenExchangeURL string
}

func (c *TokenExchangeConfig) RegisterFlags(prefix string, fs *flag.FlagSet) {
	fs.StringVar(&c.Token, prefix+".token", "", "Token used to perform the exchange request.")
	fs.StringVar(&c.TokenExchangeURL, prefix+".token-exchange-url", "", "Url called to perform exchange request.")
}
