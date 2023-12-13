package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	gocache "github.com/patrickmn/go-cache"
)

// The Cache interface caches values in a persistent or ephemeral cache database
type Cache interface {
	// Get retrieves the data at "key" in the cache source as an io.Reader, and a bool denoting whether the key was found or not.
	// For caching databases that don't automatically remove expired keys: if the cache key is found, but is expired, then "ErrorExpired" is returned.
	Get(ctx context.Context, key string) (io.Reader, bool, error)

	// Set will set the value at `key` using data read from `r`, with an expiration time of `exp`.
	// If there is a value at `key` then it will be overwritten.
	Set(ctx context.Context, key string, exp time.Duration, r io.Reader) error
}

type LocalCache struct {
	gocache.Cache
}

func NewLocalCache() *LocalCache {
	return &LocalCache{Cache: *gocache.New(5*time.Minute, time.Minute)}
}

func (lc *LocalCache) Get(ctx context.Context, key string) (io.Reader, bool, error) {
	v, ok := lc.Cache.Get(key)
	if !ok {
		return nil, false, nil
	}

	vA, ok := v.([]byte)
	if !ok {
		return nil, false, fmt.Errorf("could not read value at cache key")
	}

	return bytes.NewReader(vA), true, nil
}

func (lc *LocalCache) Set(ctx context.Context, key string, exp time.Duration, r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	lc.Cache.Set(key, b, exp)
	return nil
}
