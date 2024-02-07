package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	gocache "github.com/patrickmn/go-cache"
)

const NoExpiration = cache.NoExpiration

// The Cache interface caches values in a persistent or ephemeral cache database
type Cache interface {
	// Get retrieves the data at "key" in the cache source as an io.Reader, and a bool denoting whether the key was found or not.
	// For caching databases that don't automatically remove expired keys: if the cache key is found, but is expired, then "ErrorExpired" is returned.
	Get(ctx context.Context, key string) ([]byte, bool, error)

	// Set will set the value at `key` using data, with an expiration time of `exp`.
	// If there is a value at `key` then it will be overwritten.
	Set(ctx context.Context, key string, data []byte, exp time.Duration) error
}

type LocalCache struct {
	*gocache.Cache
}

type Config struct {
	Expiry          time.Duration
	CleanupInterval time.Duration
}

func NewLocalCache(cfg Config) *LocalCache {
	return &LocalCache{Cache: gocache.New(cfg.Expiry, cfg.CleanupInterval)}
}

func (lc *LocalCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	v, ok := lc.Cache.Get(key)
	if !ok {
		return nil, false, nil
	}

	vA, ok := v.([]byte)
	if !ok {
		return nil, false, fmt.Errorf("could not read value at cache key")
	}

	return vA, true, nil
}

func (lc *LocalCache) Set(ctx context.Context, key string, data []byte, exp time.Duration) error {
	lc.Cache.Set(key, data, exp)
	return nil
}
