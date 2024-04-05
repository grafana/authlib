package authn

import (
	"context"

	"github.com/grafana/authlib/cache"
)

type IDTokenClaims struct {
	// AuthenticatedBy is the method used to authenticate the identity.
	AuthenticatedBy string
}

func NewIDTokenVerifier(cfg VerifierConfig) *IDTokenVerifier {
	return &IDTokenVerifier{
		v: NewVerifier[IDTokenClaims](cfg, TokenTypeID),
	}
}

func NewIDTokenVerifierWithCache(cfg VerifierConfig, cache cache.Cache) *IDTokenVerifier {
	return &IDTokenVerifier{
		v: newVerifierWithKeyService[IDTokenClaims](cfg, TokenTypeID, newKeyServiceWithCache(cfg.SigningKeysURL, cache)),
	}
}

type IDTokenVerifier struct {
	v Verifier[IDTokenClaims]
}

func (e *IDTokenVerifier) FromToken(ctx context.Context, token string) (*Claims[IDTokenClaims], error) {
	return e.v.Verify(ctx, token)
}
