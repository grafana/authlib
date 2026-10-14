package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/grafana/authlib/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func keys() []byte {
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: firstKeyID, Key: firstKey.Public(), Algorithm: string(jose.ES256)},
		{KeyID: secondKeyId, Key: secondKey.Public(), Algorithm: string(jose.ES256)},
	}})
	if err != nil {
		panic(fmt.Sprintf("expect to be able to encode json: %v", err))
	}
	return data
}

func TestDefaultKeyRetriever_Get(t *testing.T) {
	var calls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(keys())
	}))
	service := NewKeyRetriever(KeyRetrieverConfig{
		SigningKeysURL: server.URL,
	})

	require.NotNil(t, service)
	require.NotNil(t, service.c)

	t.Run("should fetched key if not cached", func(t *testing.T) {
		key, err := service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)
		require.NotNil(t, key)
		assert.Equal(t, firstKeyID, key.KeyID)
		assert.Equal(t, calls, 1)
	})

	t.Run("should return cached key", func(t *testing.T) {
		key, err := service.Get(context.Background(), secondKeyId)
		require.NoError(t, err)
		require.NotNil(t, key)
		assert.Equal(t, secondKeyId, key.KeyID)
		assert.Equal(t, calls, 1)
	})

	t.Run("should cache invalid key", func(t *testing.T) {
		key, err := service.Get(context.Background(), "invalid")
		require.ErrorIs(t, err, ErrInvalidSigningKey)
		require.Nil(t, key)
		assert.Equal(t, calls, 2)

		for range 5 {
			key, err := service.Get(context.Background(), "invalid")
			require.ErrorIs(t, err, ErrInvalidSigningKey)
			require.Nil(t, key)
			assert.Equal(t, calls, 2)
		}
	})
}

func TestWithKeyRetrieverCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(keys())
	}))

	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})

	tc := &testCache{data: make(map[string][]byte)}

	// Create a new retriever with the test cache.
	service := NewKeyRetriever(KeyRetrieverConfig{
		SigningKeysURL: server.URL,
	}, WithKeyRetrieverCache(tc))

	require.NotNil(t, service, "service should not be nil")
	require.NotNil(t, service.c, "there should be a cache")
	require.Equal(t, tc, service.c, "the cache should be the one passed in the options")

	// Validate that the key is not in the cache
	data, err := tc.Get(context.Background(), firstKeyID)
	require.Error(t, err, "the initial cache should be empty")
	require.Nil(t, data, "the initial cache should be empty")

	// The cache is empty, so the implementation should fetch the key.
	key, err := service.Get(context.Background(), firstKeyID)
	require.NoError(t, err, "getting a key not present in the cache should not return an error")
	require.NotNil(t, key, "Get should return a key")
	assert.Equal(t, firstKeyID, key.KeyID, "the key should match the one requested")

	// If the implementation called the cache, the data should be there now.
	data, err = tc.Get(context.Background(), firstKeyID)
	require.NoError(t, err, "the cache should have the key now")
	require.NotNil(t, data, "the cache should have the key now")

	// Decode the data to validate that it matches the key. We know the
	// entries in the cache are JSON-encoded keys.
	var jwk jose.JSONWebKey
	require.NoError(t, json.Unmarshal(data, &jwk), "the data should be valid JSON")
	require.Equal(t, firstKeyID, jwk.KeyID, "the key id should match the one requested")

	// Remove the key from the cache; the implementation should still return the key.
	err = tc.Delete(context.Background(), firstKeyID)
	require.NoError(t, err, "deleting the key from the cache should not return an error")

	key, err = service.Get(context.Background(), firstKeyID)
	require.NoError(t, err, "getting a key not present in the cache should not return an error")
	require.NotNil(t, key, "Get should return a key")
	assert.Equal(t, firstKeyID, key.KeyID, "the key should match the one requested")

	// Retrieve an invalid key; the implementation should return an error.
	key, err = service.Get(context.Background(), "invalid")
	require.ErrorIs(t, err, ErrInvalidSigningKey)
	require.Nil(t, key)

	// The implementation adds invalid keys to the cache to prevent re-fetching.
	data, err = tc.Get(context.Background(), "invalid")
	require.NoError(t, err, "the cache should have the invalid key now")
	require.NotNil(t, data, "the cache should have the invalid key now")
	require.Empty(t, data, "the cache should have the invalid key now")
}

func keySet(keyIDs ...string) []byte {
	set := jose.JSONWebKeySet{}
	for _, keyID := range keyIDs {
		set.Keys = append(set.Keys, jose.JSONWebKey{KeyID: keyID, Key: firstKey.Public(), Algorithm: string(jose.ES256)})
	}
	data, err := json.Marshal(set)
	if err != nil {
		panic(fmt.Sprintf("expect to be able to encode json: %v", err))
	}
	return data
}

// refreshTestServer serves whatever respond returns and counts calls.
type refreshTestServer struct {
	calls   atomic.Int32
	respond atomic.Pointer[func(w http.ResponseWriter)]
	*httptest.Server
}

func newRefreshTestServer(t *testing.T) *refreshTestServer {
	t.Helper()

	s := &refreshTestServer{}
	s.serve(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(keys())
	})
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.calls.Add(1)
		(*s.respond.Load())(w)
	}))
	t.Cleanup(s.Close)

	return s
}

func (s *refreshTestServer) serve(fn func(w http.ResponseWriter)) {
	s.respond.Store(&fn)
}

func (s *refreshTestServer) serveKeys(keyIDs ...string) {
	s.serve(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(keySet(keyIDs...))
	})
}

func (s *refreshTestServer) serveError() {
	s.serve(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusInternalServerError)
	})
}

// newRefreshTestRetriever returns a retriever whose clock the test controls.
func newRefreshTestRetriever(t *testing.T, url string) (*DefaultKeyRetriever, func(time.Duration)) {
	t.Helper()

	now := time.Now()
	var mu sync.Mutex
	service := NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: url})
	service.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	return service, advance
}

func eventuallyCalls(t *testing.T, server *refreshTestServer, want int32) {
	t.Helper()
	require.Eventually(t, func() bool { return server.calls.Load() == want }, 2*time.Second, 5*time.Millisecond)
}

func TestDefaultKeyRetriever_BackgroundRefresh(t *testing.T) {
	t.Run("serves cached key and refreshes in the background once the interval has passed", func(t *testing.T) {
		server := newRefreshTestServer(t)
		service, advance := newRefreshTestRetriever(t, server.URL)

		key, err := service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)
		assert.Equal(t, firstKeyID, key.KeyID)
		assert.EqualValues(t, 1, server.calls.Load())

		advance(defaultKeyRefreshInterval - time.Second)
		key, err = service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)
		assert.Equal(t, firstKeyID, key.KeyID)
		assert.EqualValues(t, 1, server.calls.Load())

		advance(time.Second)
		key, err = service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)
		assert.Equal(t, firstKeyID, key.KeyID)
		eventuallyCalls(t, server, 2)

		key, err = service.Get(context.Background(), secondKeyId)
		require.NoError(t, err)
		assert.Equal(t, secondKeyId, key.KeyID)
		time.Sleep(20 * time.Millisecond)
		assert.EqualValues(t, 2, server.calls.Load())
	})

	t.Run("keeps serving cached keys when the refresh fails", func(t *testing.T) {
		server := newRefreshTestServer(t)
		service, advance := newRefreshTestRetriever(t, server.URL)

		_, err := service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)

		server.serveError()

		for attempt := int32(2); attempt <= 3; attempt++ {
			advance(defaultKeyRefreshInterval)
			key, err := service.Get(context.Background(), firstKeyID)
			require.NoError(t, err)
			assert.Equal(t, firstKeyID, key.KeyID)
			eventuallyCalls(t, server, attempt)

			key, err = service.Get(context.Background(), secondKeyId)
			require.NoError(t, err)
			assert.Equal(t, secondKeyId, key.KeyID)
			time.Sleep(20 * time.Millisecond)
			assert.EqualValues(t, attempt, server.calls.Load(), "a failed refresh should not be retried before the interval passes")
		}
	})

	t.Run("treats an empty key set as a failed refresh", func(t *testing.T) {
		server := newRefreshTestServer(t)
		service, advance := newRefreshTestRetriever(t, server.URL)

		_, err := service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)

		server.serveKeys()
		advance(defaultKeyRefreshInterval)

		_, err = service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)
		eventuallyCalls(t, server, 2)

		key, err := service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)
		assert.Equal(t, firstKeyID, key.KeyID)
	})

	t.Run("drops keys removed from the key set after a successful refresh", func(t *testing.T) {
		server := newRefreshTestServer(t)
		service, advance := newRefreshTestRetriever(t, server.URL)

		_, err := service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)

		server.serveKeys(secondKeyId, "key-3")
		advance(defaultKeyRefreshInterval)

		_, err = service.Get(context.Background(), secondKeyId)
		require.NoError(t, err)
		eventuallyCalls(t, server, 2)

		key, err := service.Get(context.Background(), "key-3")
		require.NoError(t, err)
		assert.Equal(t, "key-3", key.KeyID)
		assert.EqualValues(t, 2, server.calls.Load())

		key, err = service.Get(context.Background(), firstKeyID)
		require.ErrorIs(t, err, ErrInvalidSigningKey)
		require.Nil(t, key)
		assert.EqualValues(t, 3, server.calls.Load(), "an unknown key triggers a synchronous fetch")
	})

	t.Run("concurrent requests share a single background refresh", func(t *testing.T) {
		server := newRefreshTestServer(t)
		service, advance := newRefreshTestRetriever(t, server.URL)

		_, err := service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)

		advance(defaultKeyRefreshInterval)

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				key, err := service.Get(context.Background(), firstKeyID)
				assert.NoError(t, err)
				assert.Equal(t, firstKeyID, key.KeyID)
			}()
		}
		wg.Wait()

		eventuallyCalls(t, server, 2)
		time.Sleep(50 * time.Millisecond)
		assert.EqualValues(t, 2, server.calls.Load())
	})

	t.Run("respects a custom refresh interval", func(t *testing.T) {
		server := newRefreshTestServer(t)
		service := NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: server.URL}, WithKeyRefreshInterval(time.Hour))
		now := time.Now()
		service.now = func() time.Time { return now }

		_, err := service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)

		now = now.Add(defaultKeyRefreshInterval)
		_, err = service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)
		time.Sleep(20 * time.Millisecond)
		assert.EqualValues(t, 1, server.calls.Load())

		now = now.Add(time.Hour)
		_, err = service.Get(context.Background(), firstKeyID)
		require.NoError(t, err)
		eventuallyCalls(t, server, 2)
	})
}

// testCache implements the Cache interface for testing purposes.
type testCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

var _ cache.Cache = (*testCache)(nil)

func (cache *testCache) Get(ctx context.Context, key string) ([]byte, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	item, ok := cache.data[key]
	if !ok {
		return nil, errors.New("not found")
	}

	return item, nil
}

func (cache *testCache) Set(ctx context.Context, key string, value []byte, expire time.Duration) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.data[key] = value

	return nil
}

func (cache *testCache) Delete(ctx context.Context, key string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	delete(cache.data, key)

	return nil
}
