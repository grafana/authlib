package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
)

type KeyRetriever interface {
	Get(ctx context.Context, keyID string) (*jose.JSONWebKey, error)
}

type DefaultKeyRetrieverOption func(*DefaultKeyRetriever)

// WithHTTPClientKeyRetrieverOpt allows setting the HTTP client to be used by the key retriever.
func WithHTTPClientKeyRetrieverOpt(client *http.Client) DefaultKeyRetrieverOption {
	return func(c *DefaultKeyRetriever) {
		c.client = client
	}
}

func WithKeyRetrieverCache(cache cache.Cache) DefaultKeyRetrieverOption {
	return func(c *DefaultKeyRetriever) {
		c.c = cache
	}
}

// WithKeyRefreshInterval sets how long cached keys are served before a
// background refresh of the key set is attempted. Defaults to 10 minutes.
func WithKeyRefreshInterval(interval time.Duration) DefaultKeyRetrieverOption {
	return func(c *DefaultKeyRetriever) {
		c.refreshInterval = interval
	}
}

const (
	negativeCacheTTL          = 10 * time.Minute
	cacheCleanupInterval      = 10 * time.Minute
	defaultKeyRefreshInterval = 10 * time.Minute
	backgroundRefreshTimeout  = 30 * time.Second
)

func NewKeyRetriever(cfg KeyRetrieverConfig, opt ...DefaultKeyRetrieverOption) *DefaultKeyRetriever {
	s := &DefaultKeyRetriever{
		cfg:             cfg,
		c:               nil, // See below.
		client:          http.DefaultClient,
		s:               &singleflight.Group{},
		refreshInterval: defaultKeyRefreshInterval,
		now:             time.Now,
		knownKeyIDs:     map[string]struct{}{},
	}

	for _, o := range opt {
		o(s)
	}

	// If the options did not set the cache, create a new local cache.
	//
	// This has to be done this way because the cache that is created by
	// the cache.NewLocalCache function spawns a goroutine that cannot be
	// trivially stopped. It is set up to stop when the object is garbage
	// collected, but in the general case, the calling code will not have
	// control over that.
	if s.c == nil {
		s.c = cache.NewLocalCache(cache.Config{
			Expiry:          negativeCacheTTL,
			CleanupInterval: cacheCleanupInterval,
		})
	}

	return s
}

// DefaultKeyRetriever fetches signing keys from a JWKS endpoint and caches
// them without expiry. Known keys are served from the cache and the key set
// is refreshed in the background, at most once per refresh interval, when a
// key is requested. A failed refresh keeps the current keys; a successful
// refresh replaces them, dropping keys no longer published by the endpoint.
type DefaultKeyRetriever struct {
	cfg             KeyRetrieverConfig
	client          *http.Client
	s               *singleflight.Group
	c               cache.Cache
	refreshInterval time.Duration
	now             func() time.Time

	mu          sync.Mutex
	nextRefresh time.Time

	// Only accessed inside the singleflight fetch, which never runs concurrently with itself.
	knownKeyIDs map[string]struct{}
}

func (s *DefaultKeyRetriever) Get(ctx context.Context, keyID string) (*jose.JSONWebKey, error) {
	if jwk, ok := s.getCachedItem(ctx, keyID); ok {
		s.refreshInBackgroundIfDue(ctx)
		if jwk == nil {
			return nil, ErrInvalidSigningKey
		}
		return jwk, nil
	}

	if err := s.refresh(ctx); err != nil {
		return nil, err
	}

	jwk, ok := s.getCachedItem(ctx, keyID)
	if !ok {
		// Key still don't exist after a re-fetch.
		// Cache the invalid key to prevent re-fetch
		// for known invalid keys.
		s.setEmptyCacheItem(ctx, keyID)
	}

	if jwk == nil {
		return nil, ErrInvalidSigningKey
	}

	return jwk, nil
}

func (s *DefaultKeyRetriever) refreshInBackgroundIfDue(ctx context.Context) {
	if !s.claimRefresh() {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), backgroundRefreshTimeout)
		defer cancel()

		_ = s.refresh(ctx)
	}()
}

// claimRefresh reports whether a refresh is due and, if so, schedules the
// next one, so that a single caller starts each background refresh.
func (s *DefaultKeyRetriever) claimRefresh() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if now.Before(s.nextRefresh) {
		return false
	}
	s.nextRefresh = now.Add(s.refreshInterval)

	return true
}

// refresh fetches the key set and replaces the cached keys. Concurrent calls
// share a single fetch.
func (s *DefaultKeyRetriever) refresh(ctx context.Context) error {
	_, err, _ := s.s.Do("fetch", func() (any, error) {
		jwks, err := s.fetchJWKS(ctx)
		if err != nil {
			return nil, err
		}

		s.storeKeys(ctx, jwks)

		return nil, nil
	})

	return err
}

func (s *DefaultKeyRetriever) fetchJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.cfg.SigningKeysURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request error", ErrFetchingSigningKey)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrFetchingSigningKey
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("%w: unable to decode response", ErrFetchingSigningKey)
	}

	// An empty key set would invalidate every token; treat it as a failed fetch.
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("%w: empty key set", ErrFetchingSigningKey)
	}

	return &jwks, nil
}

func (s *DefaultKeyRetriever) storeKeys(ctx context.Context, jwks *jose.JSONWebKeySet) {
	published := make(map[string]struct{}, len(jwks.Keys))
	for i := range jwks.Keys {
		s.setCachedItem(ctx, jwks.Keys[i])
		published[jwks.Keys[i].KeyID] = struct{}{}
	}

	// The cache cannot list its entries, so drop unpublished keys using the IDs stored last time.
	for keyID := range s.knownKeyIDs {
		if _, ok := published[keyID]; !ok {
			_ = s.c.Delete(ctx, keyID)
		}
	}
	s.knownKeyIDs = published

	s.mu.Lock()
	s.nextRefresh = s.now().Add(s.refreshInterval)
	s.mu.Unlock()
}

func (s *DefaultKeyRetriever) getCachedItem(ctx context.Context, keyID string) (*jose.JSONWebKey, bool) {
	data, err := s.c.Get(ctx, keyID)
	// error is a noop for local cache
	if err != nil {
		return nil, false
	}

	// we cache invalid keys as a empty byte slice
	if len(data) == 0 {
		return nil, true
	}

	var jwk jose.JSONWebKey
	// We should not fail to decode the jwk, all items in the cache are gob encoded [jose.JSONWebKey].
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&jwk); err != nil {
		return nil, false
	}

	return &jwk, true
}

func (s *DefaultKeyRetriever) setCachedItem(ctx context.Context, key jose.JSONWebKey) {
	buf := bytes.Buffer{}
	if err := json.NewEncoder(&buf).Encode(&key); err != nil {
		return
	}

	// Set cannot fail when using local cache
	_ = s.c.Set(ctx, key.KeyID, buf.Bytes(), cache.NoExpiration)
}

func (s *DefaultKeyRetriever) setEmptyCacheItem(ctx context.Context, keyID string) {
	// Set cannot fail when using local cache
	_ = s.c.Set(ctx, keyID, []byte{}, negativeCacheTTL)
}
