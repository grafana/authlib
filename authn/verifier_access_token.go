package authn

import (
	"context"

	"github.com/grafana/authlib/cache"
)

type AccessTokenClaims struct {
	// Access policy scopes
	Scopes []string `json:"scopes"`
	// Grafana roles
	Permissions []string `json:"permissions"`
	// On-behalf-of user
	DelegatedPermissions []string `json:"delegatedPermissions"`
}

func NewAccessExtractor(cfg VerifierConfig) *AccessExtractor {
	return &AccessExtractor{
		v: NewVerifier[AccessTokenClaims](cfg, TypeAccessToken),
	}
}

func NewAccessExtractorWithCache(cfg VerifierConfig, cache cache.Cache) *AccessExtractor {
	return &AccessExtractor{
		v: newVerifierWithKeyService[AccessTokenClaims](cfg, TypeAccessToken, newKeyServiceWithCache(cfg.SigningKeysURL, cache)),
	}
}

type AccessExtractor struct {
	v Verifier[AccessTokenClaims]
}

func (e *AccessExtractor) FromToken(ctx context.Context, token string) (*Claims[AccessTokenClaims], error) {
	return e.v.Verify(ctx, token)
}
