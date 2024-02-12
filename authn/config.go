package authn

import (
	"flag"
	"strings"
)

type IDVerifierConfig struct {
	SigningKeyURL    string   `yaml:"signingKeysUrl"`
	AllowedAudiences []string `yaml:"allowedAudiences"`
}

func (c *IDVerifierConfig) RegisterFlags(prefix string, fs *flag.FlagSet) {
	fs.StringVar(&c.SigningKeyURL, prefix+".signing-keys-url", "", "URL to jwks endpoint")

	fs.Func(prefix+".allowed-audiences", "Specifies a comma-separated list of allowed audiences.", func(v string) error {
		c.AllowedAudiences = strings.Split(v, ",")
		return nil
	})
}
