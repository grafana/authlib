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

	"github.com/go-jose/go-jose/v3"
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

func TestWithCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(keys())
	}))

	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})

	tc := &testCache{data: make(map[string][]byte)}

	service := NewKeyRetriever(KeyRetrieverConfig{
		SigningKeysURL: server.URL,
	}, WithCache(tc))

	require.NotNil(t, service, "service should not be nil")
	require.NotNil(t, service.c, "there should be a cache")
	require.Equal(t, tc, service.c, "the cache should be the one passed in the options")

	// The cache is empty, so the implementation should fetch the key.
	key, err := service.Get(context.Background(), firstKeyID)
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, firstKeyID, key.KeyID)

	// If the implementation called the cache, the data should be there.
	data, err := tc.Get(context.Background(), firstKeyID)
	require.NoError(t, err)
	require.NotNil(t, data)

	// Remove the key from the cache; the implementation should still return the key.
	err = tc.Delete(context.Background(), firstKeyID)
	require.NoError(t, err)

	key, err = service.Get(context.Background(), firstKeyID)
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, firstKeyID, key.KeyID)

	// Retrieve an invalid key; the implementation should return an error.
	key, err = service.Get(context.Background(), "invalid")
	require.ErrorIs(t, err, ErrInvalidSigningKey)
	require.Nil(t, key)

	// The implementation adds invalid keys to the cache to prevent re-fetching.
	data, err = tc.Get(context.Background(), "invalid")
	require.NoError(t, err)
	require.NotNil(t, data)
	require.Empty(t, data)
}

type testCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

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
