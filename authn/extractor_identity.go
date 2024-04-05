package authn

import (
	"context"

	"github.com/grafana/authlib/cache"
)

type IDTokenClaims struct {
	// AuthenticatedBy is the method used to authenticate the identity.
	AuthenticatedBy string
}

func NewIdentityExtractor(cfg VerifierConfig) *IdentityExtractor {
	return &IdentityExtractor{
		v: NewVerifier[IDTokenClaims](cfg, TypeIDToken),
	}
}

func NewIdentityExtractorWithCache(cfg VerifierConfig, cache cache.Cache) *IdentityExtractor {
	return &IdentityExtractor{
		v: newVerifierWithKeyService[IDTokenClaims](cfg, TypeIDToken, newKeyServiceWithCache(cfg.SigningKeysURL, cache)),
	}
}

type IdentityExtractor struct {
	v Verifier[IDTokenClaims]
}

func (e *IdentityExtractor) FromToken(ctx context.Context, token string) (*Claims[IDTokenClaims], error) {
	return e.v.Verify(ctx, token)
}
