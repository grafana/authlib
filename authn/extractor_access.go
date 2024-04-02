package authn

import (
	"context"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/grafana/authlib/cache"
)

const (
	tenantPrefixOrg   = "org:"
	tenantPrefixStack = "stack:"
)

type accessClaims struct {
	jwt.Claims
	Scopes      []string `json:"scopes"`
	Permissions []string `json:"permissions"`
}

type AccessToken struct {
	// TenantID is an prefixed tenant identitfier either `org:` or `stack:`.
	TenantID string
	// Access policy scopes
	Scopes []string `json:"scopes"`
	// Grafana roles
	Permissions []string `json:"permissions"`
}

func NewAccessExtractor(cfg IDVerifierConfig) *AccessExtractor {
	return &AccessExtractor{
		v: NewVerifier[accessClaims](cfg),
	}
}

func NewAccessExtractorWithCache(cfg IDVerifierConfig, cache cache.Cache) *AccessExtractor {
	return &AccessExtractor{
		v: newVerifierWithKeyService[accessClaims](cfg, newKeyServiceWithCache(cfg.SigningKeysURL, cache)),
	}
}

type AccessExtractor struct {
	v Verifier[accessClaims]
}

func (e *AccessExtractor) FromToken(ctx context.Context, token string) (*AccessToken, error) {
	claims, err := e.v.Verify(ctx, token, TypeAccessToken)
	if err != nil {
		return nil, err
	}

	access := &AccessToken{
		Scopes:      claims.Rest.Scopes,
		Permissions: claims.Rest.Permissions,
	}

	for _, aud := range claims.Audience {
		if strings.HasPrefix(aud, tenantPrefixOrg) || strings.HasPrefix(aud, tenantPrefixStack) {
			access.TenantID = aud
			break
		}

	}

	return access, nil
}
