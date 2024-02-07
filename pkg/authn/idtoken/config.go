package idtoken

import (
	"flag"
	"strings"
)

type Config struct {
	SigningKeyURL    string   `yaml:"signingKeysUrl"`
	AllowedAudiences []string `yaml:"allowedAudiences"`
}

func (c *Config) RegisterFlags(prefix string, fs flag.FlagSet) {
	fs.StringVar(&c.SigningKeyURL, prefix+".signing-keys-url", "", "usage")
	registerAllowedAudiences(c, prefix, &fs)
}

func registerAllowedAudiences(cfg *Config, prefix string, f *flag.FlagSet) {
	var allowedAudiences string
	f.StringVar(&allowedAudiences,
		prefix+".allowed-audiences",
		"",
		"Specifies a comma-separated list of allowed audiences.")
	cfg.AllowedAudiences = strings.Split(allowedAudiences, ",")
}
