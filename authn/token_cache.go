package authn

import (
	"context"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
)

// tokenCache caches short-lived bearer tokens minted by auth-api, keyed by an opaque cache key
// the caller derives from its own request shape. Concurrent calls for the same key are coalesced
// via singleflight, and cache TTL is taken from each minted token's own JWT expiry. Shared by
// every auth-api token client in this package so the cache/coalescing logic is written once
// instead of once per capability (exchange, derive, ...).
type tokenCache struct {
	cache   cache.Cache
	singlef singleflight.Group
}

// getOrFetch returns the cached token for key, or calls fetch to mint one and caches it (best
// effort) under key before returning. hit reports whether the value came from cache, for callers
// that want to record it on their span.
func (t *tokenCache) getOrFetch(ctx context.Context, key string, fetch func() (string, error)) (token string, hit bool, err error) {
	if token, ok := t.get(ctx, key); ok {
		return token, true, nil
	}

	v, err, _ := t.singlef.Do(key, func() (interface{}, error) {
		token, err := fetch()
		if err != nil {
			return nil, err
		}
		// A valid token was already minted, so a caching failure shouldn't fail the call.
		_ = t.set(ctx, key, token)
		return token, nil
	})
	if err != nil {
		return "", false, err
	}
	return v.(string), false, nil
}

func (t *tokenCache) get(ctx context.Context, key string) (string, bool) {
	if token, err := t.cache.Get(ctx, key); err == nil {
		return string(token), true
	}
	return "", false
}

func (t *tokenCache) set(ctx context.Context, key, token string) error {
	const cacheLeeway = 15 * time.Second

	parsed, err := jwt.ParseSigned(token, tokenSignAlgs)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	var claims jwt.Claims
	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return fmt.Errorf("failed to extract claims from the token: %w", err)
	}

	remaining := time.Until(claims.Expiry.Time())
	if remaining <= cacheLeeway {
		// Non-positive cache durations can mean no expiration.
		return nil
	}

	return t.cache.Set(ctx, key, []byte(token), remaining-cacheLeeway)
}
