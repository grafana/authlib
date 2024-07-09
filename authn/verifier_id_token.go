package authn

import (
	"context"
)

type IDTokenClaims struct {
	// Namespace takes the form of '<type>-<id>', '*' means all namespaces.
	// Type can be either org or stack.
	Namespace string `json:"namespace"`
	// AuthenticatedBy is the method used to authenticate the identity.
	AuthenticatedBy string `json:"authenticatedBy"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"email_verified"`
	Login           string `json:"login"`
}

func (c IDTokenClaims) NamespaceMatches(namespace string) bool {
	if c.Namespace == "*" {
		return true
	}
	return c.Namespace == namespace
}

func NewIDTokenVerifier(cfg VerifierConfig, keys KeyRetriever) *IDTokenVerifier {
	return &IDTokenVerifier{
		v: NewVerifier[IDTokenClaims](cfg, TokenTypeID, keys),
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
