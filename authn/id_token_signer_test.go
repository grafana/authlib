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

func TestNewIDTokenSignerClient(t *testing.T) {
	t.Run("should not be able to create client without token", func(t *testing.T) {
		_, err := NewIDTokenSignerClient(IDTokenSignerConfig{
			SignIDTokenURL: "some-url",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingConfig)
	})

	t.Run("should not be able to create client without url", func(t *testing.T) {
		_, err := NewIDTokenSignerClient(IDTokenSignerConfig{
			Token: "some-token",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingConfig)
	})

	t.Run("should be able to create client", func(t *testing.T) {
		_, err := NewIDTokenSignerClient(IDTokenSignerConfig{
			Token:          "some-token",
			SignIDTokenURL: "some-url",
		})
		require.NoError(t, err)
	})
}

func Test_IDTokenSignerClient_SignIDToken(t *testing.T) {
	expiresIn := 10 * time.Minute
	setup := func(srv *httptest.Server, opts ...IDTokenSignerClientOpts) *IDTokenSignerClient {
		c, err := NewIDTokenSignerClient(IDTokenSignerConfig{
			Token:          "some-token",
			SignIDTokenURL: srv.URL,
		}, opts...)
		require.NoError(t, err)
		return c
	}

	t.Run("should return error if subject is empty", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))
		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{Namespace: "stacks-1"})
		assert.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("should return error if namespace is empty", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))
		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1"})
		assert.ErrorIs(t, err, ErrMissingNamespace)
		assert.Nil(t, res)
	})

	t.Run("should return error for unexpected server response", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("{}"))
		})))
		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1", Namespace: "stacks-1"})
		assert.ErrorIs(t, err, ErrInvalidSignIDTokenResponse)
		assert.Nil(t, res)
	})

	t.Run("should send correct request body and headers", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer some-token", r.Header.Get("Authorization"))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "0", r.Header.Get("X-Org-ID"))

			var body signIDTokenRequestBody
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "user:1", body.Claims.Subject)
			assert.Equal(t, "stacks-12345", body.Namespace)

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
		})))

		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1", Namespace: "stacks-12345"})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.Token)
	})

	t.Run("should send extra claims in request body", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body signIDTokenRequestBody
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "user:1", body.Claims.Subject)
			assert.Equal(t, "stacks-1", body.Namespace)
			assert.Equal(t, "alice@example.com", body.Extra["email"])
			assert.Equal(t, "alice", body.Extra["username"])
			assert.Equal(t, "user", body.Extra["type"])

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
		})))

		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{
			Subject:   "user:1",
			Namespace: "stacks-1",
			Extra: map[string]any{
				"email":    "alice@example.com",
				"username": "alice",
				"type":     "user",
			},
		})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.NotEmpty(t, res.Token)
	})

	t.Run("should use per-request WithSignerHeaders to override defaults", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "12345", r.Header.Get("X-Org-ID"))
			assert.Equal(t, `[{"type":"stack","identifier":"12345"}]`, r.Header.Get("X-Realms"))

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
		})))

		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1", Namespace: "stacks-1"}, WithSignerHeaders(map[string]string{
			"X-Org-ID": "12345",
			"X-Realms": `[{"type":"stack","identifier":"12345"}]`,
		}))
		assert.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("should use per-request func option to modify request", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "42", r.Header.Get("X-Org-ID"))
			assert.Equal(t, "custom-value", r.Header.Get("X-Custom"))

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
		})))

		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1", Namespace: "stacks-1"}, func(r *http.Request) {
			r.Header.Set("X-Org-ID", "42")
			r.Header.Set("X-Custom", "custom-value")
		})
		assert.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("should cache and return token on successful sign request", func(t *testing.T) {
		var calls int
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
		})))

		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1", Namespace: "stacks-1"})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// same subject and namespace should load token from cache
		res, err = c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1", Namespace: "stacks-1"})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// different namespace should make a new request
		res, err = c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1", Namespace: "stacks-2"})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 2, calls)

		// different subject should make a new request
		res, err = c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:2", Namespace: "stacks-1"})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 3, calls)

		// same subject/namespace but different extra claims should make a new request
		res, err = c.SignIDToken(context.Background(), SignIDTokenRequest{
			Subject:   "user:1",
			Namespace: "stacks-1",
			Extra:     map[string]any{"email": "alice@example.com"},
		})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 4, calls)

		// same request with extra should hit cache
		res, err = c.SignIDToken(context.Background(), SignIDTokenRequest{
			Subject:   "user:1",
			Namespace: "stacks-1",
			Extra:     map[string]any{"email": "alice@example.com"},
		})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 4, calls)
	})

	t.Run("should return error with message from server", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status": "error", "error": "forbidden namespace"}`))
		})))

		res, err := c.SignIDToken(context.Background(), SignIDTokenRequest{Subject: "user:1", Namespace: "stacks-1"})
		assert.ErrorIs(t, err, ErrInvalidSignIDTokenResponse)
		assert.Contains(t, err.Error(), "forbidden namespace")
		assert.Nil(t, res)
	})
}
