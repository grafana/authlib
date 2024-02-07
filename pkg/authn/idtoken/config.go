package idtoken

import "flag"

type Config struct {
	SigningKeyURL    string   `yaml:"signingKeysUrl"`
	AllowedAudiences []string `yaml:"allowedAudiences"`
}

func (c *Config) RegisterFlags(prefix string, fs flag.FlagSet) {
	fs.StringVar(&c.SigningKeyURL, prefix+".signing-keys-url", "", "usage")
}
