package authn

import (
	"context"
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

func NewAccessTokenVerifier(cfg VerifierConfig, opts ...VerifierOption) *AccessTokenVerifier {
	return &AccessTokenVerifier{
		v: NewVerifier[AccessTokenClaims](cfg, TokenTypeAccess, opts...),
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
