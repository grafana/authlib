package authn

import (
	"flag"
	"strings"
)

type IDVerifierConfig struct {
	SigningKeyURL    string   `yaml:"signingKeysUrl"`
	AllowedAudiences []string `yaml:"allowedAudiences"`
}

func (c *IDVerifierConfig) RegisterFlags(prefix string, fs flag.FlagSet) {
	fs.StringVar(&c.SigningKeyURL, prefix+".signing-keys-url", "", "URL to jwks endpoint")

	var allowedAudiences string
	fs.StringVar(&allowedAudiences, prefix+".allowed-audiences", "", "Specifies a comma-separated list of allowed audiences.")
	c.AllowedAudiences = strings.Split(allowedAudiences, ",")
}
