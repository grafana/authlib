package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/internal/httpclient"
)

// Provided for mockability of client
type TokenExchanger interface {
	Exchange(ctx context.Context, r TokenExchangeRequest) (*TokenExchangeResponse, error)
}

var _ TokenExchanger = &TokenExchangeClient{}

// ExchangeClientOpts allows setting custom parameters during construction.
type ExchangeClientOpts func(c *TokenExchangeClient)

// WithHTTPClient allows setting the HTTP client to be used by the token exchange client.
func WithHTTPClient(client *http.Client) ExchangeClientOpts {
	return func(c *TokenExchangeClient) {
		c.client = client
	}
}

func NewTokenExchangeClient(cfg TokenExchangeConfig, opts ...ExchangeClientOpts) (*TokenExchangeClient, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: missing required token", ErrMissingConfig)
	}

	if cfg.TokenExchangeURL == "" {
		return nil, fmt.Errorf("%w: missing required token exchange url", ErrMissingConfig)
	}

	c := &TokenExchangeClient{
		cache: cache.NewLocalCache(cache.Config{
			CleanupInterval: 5 * time.Minute,
		}),
		cfg:     cfg,
		singlef: singleflight.Group{},
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.client == nil {
		c.client = httpclient.New()
	}

	return c, nil

}

type TokenExchangeClient struct {
	cache   cache.Cache
	cfg     TokenExchangeConfig
	client  *http.Client
	singlef singleflight.Group
}

type TokenExchangeRequest struct {
	// Namespace token should be signed with.
	// Use wildcard '*' to create a token for all namespaces.
	Namespace string `json:"namespace"`
	// Audiences token should be signed with.
	Audiences []string `json:"audiences"`
}

type TokenExchangeResponse struct {
	Token string
}

func (r TokenExchangeRequest) hash() string {
	br := strings.Builder{}
	br.WriteString(r.Namespace)
	br.WriteByte('-')
	sort.Strings(r.Audiences)
	br.WriteString(strings.Join(r.Audiences, "-"))

	return br.String()
}

type tokenExchangeResponse struct {
	Data   tokenExchangeData `json:"data"`
	Status string            `json:"status"`
	Error  string            `json:"error"`
}

type tokenExchangeData struct {
	Token string `json:"token"`
}

func (c *TokenExchangeClient) Exchange(ctx context.Context, r TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if r.Namespace == "" {
		return nil, ErrMissingNamespace
	}

	if len(r.Audiences) == 0 {
		return nil, ErrMissingAudiences
	}

	key := r.hash()
	token, ok := c.getCache(ctx, key)
	if ok {
		return &TokenExchangeResponse{Token: token}, nil
	}

	resp, err, _ := c.singlef.Do(key, func() (interface{}, error) {
		data, err := json.Marshal(&r)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidExchangeResponse, err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenExchangeURL, bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to build http request: %w", err)
		}

		res, err := c.client.Do(c.withHeaders(req))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidExchangeResponse, err)
		}
		defer res.Body.Close()

		if res.StatusCode >= http.StatusInternalServerError {
			return nil, fmt.Errorf("%w: %s", ErrInvalidExchangeResponse, res.Status)
		}

		response := tokenExchangeResponse{}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, err
		}

		if res.StatusCode != http.StatusOK {
			if response.Error != "" {
				return nil, fmt.Errorf("%w: %s", ErrInvalidExchangeResponse, response.Error)
			}
			return nil, fmt.Errorf("%w: %s", ErrInvalidExchangeResponse, res.Status)
		}

		// FIXME: for now we ignore errors when updating the cache becasue we still
		// have a valid response to return.
		_ = c.setCache(ctx, response.Data.Token, key)
		return response, nil
	})

	if err != nil {
		return nil, err
	}

	response := resp.(tokenExchangeResponse)
	return &TokenExchangeResponse{Token: response.Data.Token}, nil
}

func (c *TokenExchangeClient) withHeaders(r *http.Request) *http.Request {
	r.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "authlib-client")

	// Always propagate system token headers.
	// These will be ignored for non system tokens.
	r.Header.Set("X-Org-ID", "0")
	r.Header.Set("X-Realms", `[{"type": "system", "identifier": "system"}]`)
	return r
}

func (c *TokenExchangeClient) getCache(ctx context.Context, key string) (string, bool) {
	if token, err := c.cache.Get(ctx, key); err == nil {
		return string(token), true
	}
	return "", false
}

func (c *TokenExchangeClient) setCache(ctx context.Context, token string, key string) error {
	const cacheLeeway = 15 * time.Second

	parsed, err := jwt.ParseSigned(token)
	if err != nil {
		return fmt.Errorf("failed to parse token: %v", err)
	}

	var claims jwt.Claims
	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return fmt.Errorf("failed to extract claims from the token: %v", err)
	}

	return c.cache.Set(ctx, key, []byte(token), time.Until(claims.Expiry.Time())-cacheLeeway)
}
