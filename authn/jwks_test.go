package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
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

		for i := 0; i < 5; i++ {
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
