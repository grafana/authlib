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

func NewAccessTokenVerifier(cfg VerifierConfig) *AccessTokenVerifier {
	return &AccessTokenVerifier{
		v: NewVerifier[AccessTokenClaims](cfg, TokenTypeAccess),
	}
}

func NewAccessTokenVerifierWithCache(cfg VerifierConfig, cache cache.Cache) *AccessTokenVerifier {
	return &AccessTokenVerifier{
		v: newVerifierWithKeyService[AccessTokenClaims](cfg, TokenTypeAccess, newKeyServiceWithCache(cfg.SigningKeysURL, cache)),
	}
}

// AccessTokenVerifier is a convenient wrapper around `Verifier`
// used to verify and authenticate Grafana issued AccessTokens.
type AccessTokenVerifier struct {
	v Verifier[AccessTokenClaims]
}

func (e *AccessTokenVerifier) Verify(ctx context.Context, token string) (*Claims[AccessTokenClaims], error) {
	return e.v.Verify(ctx, token)
}
