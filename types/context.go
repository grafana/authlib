package types

import (
	"context"
)

// The key type is unexported to prevent collisions
type key int

const (
	// claimsKey is the context key for the identity claims
	claimsKey key = iota
)

func From(ctx context.Context) (AuthInfo, bool) {
	v, ok := ctx.Value(claimsKey).(AuthInfo)
	return v, ok
}

func WithClaims(ctx context.Context, claims AuthInfo) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}
