package authn

import (
	"context"

	"github.com/grafana/authlib/claims"
)

type AccessTokenClaims struct {
	// Namespace takes the form of '<type>-<id>', '*' means all namespaces.
	// Type can be either org or stack.
	Namespace string `json:"namespace"`
	// Access policy scopes
	Scopes []string `json:"scopes"`
	// Grafana roles
	Permissions []string `json:"permissions"`
	// On-behalf-of user
	DelegatedPermissions []string `json:"delegatedPermissions"`
}

func (c AccessTokenClaims) NamespaceMatches(namespace string) bool {
	if c.Namespace == "*" {
		return true
	}
	return c.Namespace == namespace
}

func NewAccessTokenVerifier(cfg VerifierConfig, keys KeyRetriever) *AccessTokenVerifier {
	return &AccessTokenVerifier{
		v: NewVerifier[AccessTokenClaims](cfg, TokenTypeAccess, keys),
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

func (e *AccessTokenVerifier) VerifyToken(ctx context.Context, token string) (claims.TokenClaims, AccessTokenClaims, error) {
	return e.v.VerifyToken(ctx, token)
}
