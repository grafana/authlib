package authn

import (
	"context"
	"fmt"
)

type ActorClaims struct {
	Subject string       `json:"sub"`
	Actor   *ActorClaims `json:"act,omitempty"`

	// Embed IDTokenClaims for on behalf of flow.
	IDTokenClaims
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
	// ServiceIdentity is the name/identity of the service that has been created/signed the access token.
	ServiceIdentity string `json:"serviceIdentity,omitempty"`
}

func (c ActorClaims) getTypedUID() string {
	return fmt.Sprintf("%s:%s", c.Type, c.Identifier)
}

func (c ActorClaims) getK8sName() string {
	if c.DisplayName != "" {
		return c.DisplayName
	}
	if c.Username != "" {
		return c.Username
	}
	if c.Email != "" {
		return c.Email
	}
	return c.Identifier
}

func (c AccessTokenClaims) getInnermostActor() *ActorClaims {
	currentActor := c.Actor
	if currentActor != nil {
		for currentActor.Actor != nil {
			currentActor = currentActor.Actor
		}
	}

	return currentActor
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
