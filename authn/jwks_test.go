package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func keys() []byte {
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: firstKeyID, Key: fistKey.Public(), Algorithm: string(jose.ES256)},
		{KeyID: secondKeyId, Key: secondKey.Public(), Algorithm: string(jose.ES256)},
	}})
	if err != nil {
		panic(fmt.Sprintf("expect to be able to encode json: %v", err))
	}
	return data
}

func TestKeyService_Get(t *testing.T) {
	var calls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		w.Write(keys())
	}))
	service := newKeyService(server.URL)

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
