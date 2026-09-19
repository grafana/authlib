package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIDTokenDeriveClient(t *testing.T) {
	t.Run("should not be able to create client without token", func(t *testing.T) {
		_, err := NewIDTokenDeriveClient(IDTokenDeriveConfig{
			DeriveIDTokenURL: "some-url",
		})
		require.ErrorIs(t, err, ErrMissingConfig)
	})

	t.Run("should not be able to create client without url", func(t *testing.T) {
		_, err := NewIDTokenDeriveClient(IDTokenDeriveConfig{
			Token: "some-token",
		})
		require.ErrorIs(t, err, ErrMissingConfig)
	})

	t.Run("should be able to create client", func(t *testing.T) {
		_, err := NewIDTokenDeriveClient(IDTokenDeriveConfig{
			Token:            "some-token",
			DeriveIDTokenURL: "some-url",
		})
		require.NoError(t, err)
	})
}

func Test_IDTokenDeriveClient_DeriveIDToken(t *testing.T) {
	expiresIn := 10 * time.Minute
	setup := func(srv *httptest.Server, opts ...IDTokenDeriveClientOpts) *IDTokenDeriveClient {
		c, err := NewIDTokenDeriveClient(IDTokenDeriveConfig{
			Token:            "some-token",
			DeriveIDTokenURL: srv.URL,
		}, opts...)
		require.NoError(t, err)
		return c
	}

	t.Run("should return error if subject token is empty", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))
		res, err := c.DeriveIDToken(context.Background(), "", "*")
		assert.ErrorIs(t, err, ErrMissingSubjectToken)
		assert.Nil(t, res)
	})

	t.Run("should return error if namespace is empty", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))
		res, err := c.DeriveIDToken(context.Background(), signAccessToken(t, expiresIn), "")
		assert.ErrorIs(t, err, ErrMissingNamespace)
		assert.Nil(t, res)
	})

	t.Run("should return error for unexpected server response", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":"error","error":"subjectToken has no user or service account in its actor chain"}`))
		})))
		res, err := c.DeriveIDToken(context.Background(), signAccessToken(t, expiresIn), "stacks-1")
		assert.ErrorIs(t, err, ErrInvalidDeriveIDTokenResponse)
		assert.Nil(t, res)
	})

	t.Run("should send subjectToken and namespace, and cache the derived token", func(t *testing.T) {
		var calls int
		var gotBody deriveIDTokenRequestBody
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			require.Equal(t, "Bearer some-token", r.Header.Get("Authorization"))
			require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
		})))

		subjectToken := signAccessToken(t, expiresIn)

		res, err := c.DeriveIDToken(context.Background(), subjectToken, "stacks-1")
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)
		assert.Equal(t, subjectToken, gotBody.SubjectToken)
		assert.Equal(t, "stacks-1", gotBody.Namespace)

		// same subjectToken and namespace should load from cache
		res, err = c.DeriveIDToken(context.Background(), subjectToken, "stacks-1")
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// different namespace should issue a new request
		res, err = c.DeriveIDToken(context.Background(), subjectToken, "stacks-2")
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 2, calls)

		// different subjectToken should issue a new request
		res, err = c.DeriveIDToken(context.Background(), signAccessToken(t, expiresIn), "stacks-1")
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 3, calls)
	})

	t.Run("should use stable subject plus actor chain for cache key", func(t *testing.T) {
		var calls int
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
		})))

		chain := &ActorClaims{
			Subject: "access-policy:mycap",
			Actor: &ActorClaims{
				Subject: "service:gateway",
				Actor: &ActorClaims{
					Subject: "user:1",
				},
			},
		}

		token1 := signSubjectToken(t, 10*time.Minute, "access-policy:mycap", chain)
		token2 := signSubjectToken(t, 11*time.Minute, "access-policy:mycap", chain)

		_, err := c.DeriveIDToken(context.Background(), token1, "stacks-1")
		assert.NoError(t, err)
		require.Equal(t, 1, calls)

		// Same subject and actor chain (just a different expiry) should hit the cache.
		_, err = c.DeriveIDToken(context.Background(), token2, "stacks-1")
		assert.NoError(t, err)
		require.Equal(t, 1, calls)
	})
}
