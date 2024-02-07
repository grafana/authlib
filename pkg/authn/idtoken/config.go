package idtoken

import "flag"

type Config struct {
	SigningKeyURL string `yaml:"signingKeysUrl"`
}

func (c *Config) RegisterFlags(prefix string, fs flag.FlagSet) {
	fs.StringVar(&c.SigningKeyURL, prefix+".signing-keys-url", "", "usage")
}
