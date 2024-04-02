package authn

import (
	"context"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/grafana/authlib/cache"
)

type Identity struct {
	// ID is an prefixed identifier for identity such as `user:` or `service-account:`.
	ID string
	// TenantID is an prefixed tenant identitfier either `org:` or `stack:`.
	TenantID string
	// AuthenticatedBy is the method used to authenticate the identity.
	AuthenticatedBy string
}

type identityClaims struct {
	jwt.Claims
	AuthenticatedBy string
}

func NewIdentityExtractor(cfg IDVerifierConfig) *IdentityExtractor {
	return &IdentityExtractor{
		v: NewVerifier[identityClaims](cfg),
	}
}

func NewIdentityExtractorWithCache(cfg IDVerifierConfig, cache cache.Cache) *IdentityExtractor {
	return &IdentityExtractor{
		v: newVerifierWithKeyService[identityClaims](cfg, newKeyServiceWithCache(cfg.SigningKeysURL, cache)),
	}
}

type IdentityExtractor struct {
	v Verifier[identityClaims]
}

func (e *IdentityExtractor) FromToken(ctx context.Context, token string) (*Identity, error) {
	claims, err := e.v.Verify(ctx, token, TypeIDToken)
	if err != nil {
		return nil, err
	}

	identity := &Identity{
		ID:              claims.Subject,
		AuthenticatedBy: claims.Rest.AuthenticatedBy,
	}

	for _, aud := range claims.Audience {
		if strings.HasPrefix(aud, tenantPrefixOrg) || strings.HasPrefix(aud, tenantPrefixStack) {
			identity.TenantID = aud
			break
		}

	}

	return identity, nil
}
