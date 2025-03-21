package types

import (
	"context"
)

// The key type is unexported to prevent collisions
type key int

const (
	// infoKey is the context key for the identity claims
	infoKey key = iota
)

func AuthInfoFrom(ctx context.Context) (AuthInfo, bool) {
	v, ok := ctx.Value(infoKey).(AuthInfo)
	if !ok {
		return nil, false
	}

	// Validate required fields are not empty
	if v.GetUID() == "" {
		return nil, false
	}
	if v.GetIdentityType() == "" {
		return nil, false
	}
	if v.GetNamespace() == "" {
		return nil, false
	}

	return v, true
}

func WithAuthInfo(ctx context.Context, auth AuthInfo) context.Context {
	return context.WithValue(ctx, infoKey, auth)
}
