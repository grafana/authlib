package grpcutils

type GrpcAuthenticatorConfig struct {
	SigningKeysURL   string
	AllowedAudiences []string
	LegacyFallback   bool
	AllowInsecure    bool
}
