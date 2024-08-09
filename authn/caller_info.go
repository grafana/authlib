package authn

import (
	"context"

	"github.com/grafana/authlib/claims"
)

var (
	_ claims.AuthInfo = &CallerAuthInfo{}
)

// Deprecated: Use claims.AuthInfo
type CallerAuthInfo struct {
	IDTokenClaims     *Claims[IDTokenClaims]
	AccessTokenClaims Claims[AccessTokenClaims]
}

// Access implements claims.AuthInfo.
func (c *CallerAuthInfo) GetAccess() claims.AccessClaims {
	return &Access{
		claims: c.AccessTokenClaims,
	}
}

// Identity implements claims.AuthInfo.
func (c *CallerAuthInfo) GetIdentity() claims.IdentityClaims {
	if c.IDTokenClaims == nil {
		return nil
	}
	return &Identity{
		claims: *c.IDTokenClaims,
	}
}

// GetExtra implements claims.AuthInfo.
func (c *CallerAuthInfo) GetExtra() map[string][]string {
	if c.IDTokenClaims != nil && c.IDTokenClaims.token != "" {
		// Currently required for external k8s aggregation
		// but this should be removed in the not-to-distant future
		return map[string][]string{"id-token": {c.IDTokenClaims.token}}
	}
	return map[string][]string{}
}

// GetGroups implements claims.AuthInfo.
func (c *CallerAuthInfo) GetGroups() []string {
	return []string{}
}

// GetName implements claims.AuthInfo.
func (c *CallerAuthInfo) GetName() string {
	return c.IDTokenClaims.Rest.getK8sName()
}

// GetUID implements claims.AuthInfo.
func (c *CallerAuthInfo) GetUID() string {
	return c.IDTokenClaims.Rest.asTypedUID()
}

type CallerAuthInfoContextKey struct{}

// Deprecated: use claims.With(...)
func AddCallerAuthInfoToContext(ctx context.Context, info CallerAuthInfo) context.Context {
	return context.WithValue(claims.WithClaims(ctx, &info), CallerAuthInfoContextKey{}, info)
}

// Deprecated: use claims.From(...)
func GetCallerAuthInfoFromContext(ctx context.Context) (CallerAuthInfo, bool) {
	info, ok := ctx.Value(CallerAuthInfoContextKey{}).(CallerAuthInfo)
	return info, ok
}
