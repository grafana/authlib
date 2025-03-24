package authn

import (
	"context"
)

type ActorClaims struct {
	Subject              string       `json:"sub"`
	Permissions          []string     `json:"permissions,omitempty"`
	DelegatedPermissions []string     `json:"delegated_permissions,omitempty"`
	Actor                *ActorClaims `json:"act,omitempty"`
}

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
	// Actor is the user/service that is acting on behalf of the subject.
	Actor *ActorClaims `json:"act,omitempty"`
}

func NewAccessTokenVerifier(cfg VerifierConfig, keys KeyRetriever) *AccessTokenVerifier {
	return &AccessTokenVerifier{
		v: NewVerifier[AccessTokenClaims](cfg, TokenTypeAccess, keys),
	}
}

func NewUnsafeAccessTokenVerifier(cfg VerifierConfig) *AccessTokenVerifier {
	return &AccessTokenVerifier{
		v: NewUnsafeVerifier[AccessTokenClaims](cfg, TokenTypeAccess),
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
