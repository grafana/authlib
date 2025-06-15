package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenExchangeClient(t *testing.T) {
	t.Run("should not be able to create client wihtout token", func(t *testing.T) {
		_, err := NewTokenExchangeClient(TokenExchangeConfig{
			TokenExchangeURL: "some-url",
		})
		require.Error(t, err)

	})

	t.Run("should not be able to create client wihtout url", func(t *testing.T) {
		_, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token: "some-token",
		})
		require.Error(t, err)
	})

	t.Run("should be able to create client", func(t *testing.T) {
		_, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token:            "some-token",
			TokenExchangeURL: "some-url",
		})
		require.NoError(t, err)
	})
}

func Test_TokenExchangeClient_Exchange(t *testing.T) {
	expiresIn := 10 * time.Minute
	setup := func(srv *httptest.Server, opts ...ExchangeClientOpts) *TokenExchangeClient {
		c, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token:            "some-token",
			TokenExchangeURL: srv.URL,
		}, opts...)
		require.NoError(t, err)
		return c
	}

	t.Run("should return error if namespace is empty", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))
		res, err := c.Exchange(context.Background(), TokenExchangeRequest{})
		assert.ErrorIs(t, err, ErrMissingNamespace)
		assert.Nil(t, res)

	})

	t.Run("should return error if audiences is empty", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))
		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*"})
		assert.ErrorIs(t, err, ErrMissingAudiences)
		assert.Nil(t, res)
	})

	t.Run("should return error for unexpected server response", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("{}"))
		})))
		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.ErrorIs(t, err, ErrInvalidExchangeResponse)
		assert.Nil(t, res)
	})

	t.Run("should cache and return token on successful sign request", func(t *testing.T) {
		var calls int
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			require.Equal(t, r.Header.Get("Authorization"), "Bearer some-token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
			bytes.NewBuffer([]byte(`{}`))
			json.NewEncoder(&bytes.Buffer{})
		})))

		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// same namespace and audiences should load token from cache
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// different namespace should issue new token request
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "stacks-1", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 2, calls)

		// different audiences should issue new token request
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service-2"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 3, calls)
	})

	t.Run("should cache and return token on successful exchange request", func(t *testing.T) {
		var calls int
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			require.Equal(t, r.Header.Get("Authorization"), "Bearer some-token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
			bytes.NewBuffer([]byte(`{}`))
			json.NewEncoder(&bytes.Buffer{})
		})))

		tokenToBeExchanged := signAccessToken(t, expiresIn)

		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}, SubjectToken: tokenToBeExchanged})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// same namespace and audiences should load token from cache
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}, SubjectToken: tokenToBeExchanged})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// different namespace should issue new token request
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "stacks-1", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 2, calls)

		// different audiences should issue new token request
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service-2"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 3, calls)

		// different subjectToken should issue new token request
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service-2"}, SubjectToken: signAccessToken(t, expiresIn)})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 4, calls)
	})

	t.Run("should include expiration in request when provided", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestBody, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
			var request TokenExchangeRequest
			err = json.Unmarshal(requestBody, &request)
			require.NoError(t, err)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, time.Duration(*request.ExpiresIn)*time.Second) + `"}}`))
		})))

		expiresIn := 30
		res, err := c.Exchange(context.Background(), TokenExchangeRequest{
			Namespace: "*",
			Audiences: []string{"some-service"},
			ExpiresIn: &expiresIn,
		})
		assert.NoError(t, err)
		assert.NotNil(t, res)

		resultToken, err := jwt.ParseSigned(res.Token)
		require.NoError(t, err)
		var claims jwt.Claims
		err = resultToken.UnsafeClaimsWithoutVerification(&claims)
		require.NoError(t, err)
		expectedExpiry := time.Now().Add(time.Duration(expiresIn) * time.Second)
		require.InDelta(t, expectedExpiry.Unix(), claims.Expiry.Time().Unix(), 1)
	})

	t.Run("should use an alternate cache if provided", func(t *testing.T) {
		testcache := &testCache{data: make(map[string][]byte)}

		var calls int
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			require.Equal(t, r.Header.Get("Authorization"), "Bearer some-token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
			bytes.NewBuffer([]byte(`{}`))
			json.NewEncoder(&bytes.Buffer{})
		})), WithTokenExchangeClientCache(testcache))

		tokenToBeExchanged := signAccessToken(t, expiresIn)

		res1, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}, SubjectToken: tokenToBeExchanged})
		assert.NoError(t, err)
		assert.NotNil(t, res1)
		require.Equal(t, 1, calls)
		require.Len(t, testcache.data, 1)

		// same namespace and audiences should load token from cache
		res2, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}, SubjectToken: tokenToBeExchanged})
		assert.NoError(t, err)
		assert.NotNil(t, res2)
		require.Equal(t, 1, calls)
		require.Len(t, testcache.data, 1)
		require.Equal(t, res1, res2)

		// This is only testing that the cache is used, so we do not repeat the other cases here.
	})

	t.Run("should retry requests and return token on successful sign request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.Header.Get("Authorization"), "Bearer some-token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
			bytes.NewBuffer([]byte(`{}`))
			json.NewEncoder(&bytes.Buffer{})
		}))

		c, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token:            "some-token",
			TokenExchangeURL: srv.URL,
		})
		require.NoError(t, err)

		var countRequests = 0
		// brokenTransport returns a network error on the first 2 requests.
		brokenTransport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if countRequests < 2 {
					countRequests++
					return nil, fmt.Errorf("network error")
				}
				countRequests = 0
				return net.Dial(network, addr)
			},
		}
		c.client.Transport = brokenTransport

		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("should retry requests and return error after 3 failed requests", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.Header.Get("Authorization"), "Bearer some-token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
			bytes.NewBuffer([]byte(`{}`))
			json.NewEncoder(&bytes.Buffer{})
		}))

		c, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token:            "some-token",
			TokenExchangeURL: srv.URL,
		})
		require.NoError(t, err)

		var countRequests = 0
		// brokenTransport returns a network error on the first 3 requests.
		brokenTransport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if countRequests < 3 {
					countRequests++
					return nil, fmt.Errorf("network error")
				}
				countRequests = 0
				return net.Dial(network, addr)
			},
		}
		c.client.Transport = brokenTransport

		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("should retry failed requests with transient errors, like status code 500x, and return token on successful sign request", func(t *testing.T) {
		var countRequests = 0

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			countRequests++
			if countRequests < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("{}"))
				return
			}

			require.Equal(t, r.Header.Get("Authorization"), "Bearer some-token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t, expiresIn) + `"}}`))
			bytes.NewBuffer([]byte(`{}`))
			json.NewEncoder(&bytes.Buffer{})
		}))

		c, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token:            "some-token",
			TokenExchangeURL: srv.URL,
		})
		require.NoError(t, err)

		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("should not retry failed requests with permanent errors, like status code 400x", func(t *testing.T) {
		var countRequests = 0

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			countRequests++
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("{}"))
		}))

		c, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token:            "some-token",
			TokenExchangeURL: srv.URL,
		})
		require.NoError(t, err)

		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.ErrorIs(t, err, ErrInvalidExchangeResponse)
		assert.Nil(t, res)
		assert.Equal(t, countRequests, 1)
	})
}

func signAccessToken(t *testing.T, expiresIn time.Duration) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte("key"),
	}, nil)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).
		Claims(&jwt.Claims{Expiry: jwt.NewNumericDate(time.Now().Add(expiresIn))}).
		CompactSerialize()

	require.NoError(t, err)
	return token
}
