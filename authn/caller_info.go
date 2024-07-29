package authn

import "context"

type CallerAuthInfo struct {
	IDTokenClaims     *Claims[IDTokenClaims]
	AccessTokenClaims Claims[AccessTokenClaims]
}

type CallerAuthInfoContextKey struct{}

func AddCallerAuthInfoToContext(ctx context.Context, info CallerAuthInfo) context.Context {
	return context.WithValue(ctx, CallerAuthInfoContextKey{}, info)
}

func GetCallerAuthInfoFromContext(ctx context.Context) (CallerAuthInfo, bool) {
	info, ok := ctx.Value(CallerAuthInfoContextKey{}).(CallerAuthInfo)
	return info, ok
}
