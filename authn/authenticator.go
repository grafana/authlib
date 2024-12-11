package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"

	"github.com/grafana/authlib/claims"
)

type TokenProvider interface {
	AccessToken(ctx context.Context) (string, bool)
	IDToken(ctx context.Context) (string, bool)
}

func NewHTTPTokenProvider(r *http.Request) HttpTokenProvider {
	return HttpTokenProvider{r}
}

type HttpTokenProvider struct {
	r *http.Request
}

func (p HttpTokenProvider) AccessToken(ctx context.Context) (string, bool) {
	const header = "X-Access-Token"
	// Strip the 'Bearer' prefix if it exists.
	token := strings.TrimPrefix(p.r.Header.Get(header), "Bearer ")
	return token, len(token) > 0

}

func (p HttpTokenProvider) IDToken(ctx context.Context) (string, bool) {
	const header = "X-Grafana-Id"
	// Strip the 'Bearer' prefix if it exists.
	token := strings.TrimPrefix(p.r.Header.Get(header), "Bearer ")
	return token, len(token) > 0
}

func NewGRPCTokenProvider(md metadata.MD) GRPCTokenProvider {
	return GRPCTokenProvider{md}
}

type GRPCTokenProvider struct {
	md metadata.MD
}

func (p GRPCTokenProvider) AccessToken(_ context.Context) (string, bool) {
	const key = "X-Access-Token"
	values := p.md.Get(key)
	if len(values) == 0 {
		return "", false
	}

	token := values[0]
	return token, len(token) > 0
}

func (p GRPCTokenProvider) IDToken(_ context.Context) (string, bool) {
	const key = "X-Grafana-Id"
	values := p.md.Get(key)
	if len(values) == 0 {
		return "", false
	}

	token := values[0]
	return token, len(token) > 0
}

type Authenticator interface {
	Autenticate(ctx context.Context, provider TokenProvider) (claims.AuthInfo, error)
}

var _ Authenticator = (*DefaultAuthenticator)(nil)

func NewDefaultAutenticator(at *AccessTokenVerifier, id *IDTokenVerifier) *DefaultAuthenticator {
	return &DefaultAuthenticator{at, id}
}

type DefaultAuthenticator struct {
	at *AccessTokenVerifier
	id *IDTokenVerifier
}

func (a *DefaultAuthenticator) Autenticate(ctx context.Context, provider TokenProvider) (claims.AuthInfo, error) {
	atToken, ok := provider.AccessToken(ctx)
	if !ok {
		return nil, errors.New("unauthenticated")
	}

	atClaims, err := a.at.Verify(ctx, atToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token: %w", err)
	}

	idToken, ok := provider.IDToken(ctx)
	if !ok {
		return NewAccessTokenAuthInfo(*atClaims), nil
	}

	idClaims, err := a.id.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token: %w", err)
	}

	// verify that access token can operate in the same namespace as id token
	if !claims.NamespaceMatches(atClaims.Rest.Namespace, idClaims.Rest.Namespace) {
		return nil, errors.New("namespace missmatch")
	}

	return NewIDTokenAuthInfo(*atClaims, idClaims), nil
}

var _ Authenticator = (*AccessTokenAutenticator)(nil)

func NewAccessTokenAuthenticator(at *AccessTokenVerifier) *AccessTokenAutenticator {
	return &AccessTokenAutenticator{at}
}

type AccessTokenAutenticator struct {
	at *AccessTokenVerifier
}

func (a *AccessTokenAutenticator) Autenticate(ctx context.Context, provider TokenProvider) (claims.AuthInfo, error) {
	token, ok := provider.AccessToken(ctx)
	if !ok {
		return nil, errors.New("unauthenticated")
	}

	claims, err := a.at.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token: %w", err)
	}

	return NewAccessTokenAuthInfo(*claims), nil
}

var _ Authenticator = (*IDTokenAuthenticator)(nil)

func NewIDTokenAutenticator(id *IDTokenVerifier) *IDTokenAuthenticator {
	return &IDTokenAuthenticator{id}
}

type IDTokenAuthenticator struct {
	id *IDTokenVerifier
}

func (a *IDTokenAuthenticator) Autenticate(ctx context.Context, provider TokenProvider) (claims.AuthInfo, error) {
	token, ok := provider.IDToken(ctx)
	if !ok {
		return nil, errors.New("unauthenticated")
	}

	claims, err := a.id.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token: %w", err)
	}

	return NewIDTokenAuthInfo(Claims[AccessTokenClaims]{}, claims), nil
}
