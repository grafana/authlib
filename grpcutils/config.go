package grpcutils

type GrpcAuthenticatorConfig struct {
	SigningKeysURL   string
	AllowedAudiences []string
	AllowInsecure    bool
}
