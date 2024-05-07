package authn

import (
	"context"

	"github.com/grafana/authlib/cache"
)

type IDTokenClaims struct {
	// Namespace takes the form of '<type>-<id>', '*' means all namespaces.
	// Type can be either org or stack.
	Namespace string `json:"namespace"`
	// AuthenticatedBy is the method used to authenticate the identity.
	AuthenticatedBy string `json:"authenticatedBy"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"email_verified"`
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

// IDTokenVerifier is a convenient wrapper around `Verifier`
// used to verify grafana issued id tokens.
type IDTokenVerifier struct {
	v Verifier[IDTokenClaims]
}

func (e *IDTokenVerifier) Verify(ctx context.Context, token string) (*Claims[IDTokenClaims], error) {
	return e.v.Verify(ctx, token)
}
