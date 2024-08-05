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
func (c *CallerAuthInfo) Access() claims.AccessClaims {
	return &Access{
		claims: c.AccessTokenClaims,
	}
}

// Identity implements claims.AuthInfo.
func (c *CallerAuthInfo) Identity() claims.IdentityClaims {
	if c.IDTokenClaims == nil {
		return nil
	}
	return &Identity{
		claims: *c.IDTokenClaims,
	}
}

type CallerAuthInfoContextKey struct{}

func AddCallerAuthInfoToContext(ctx context.Context, info CallerAuthInfo) context.Context {
	return context.WithValue(ctx, CallerAuthInfoContextKey{}, claims.WithClaims(ctx, &info))
}

func GetCallerAuthInfoFromContext(ctx context.Context) (CallerAuthInfo, bool) {
	info, ok := ctx.Value(CallerAuthInfoContextKey{}).(CallerAuthInfo)
	return info, ok
}
