package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
)

// Set cache TTL one minute shorter than Token expiry
const tokenCacheTTL = 9 * time.Minute
const tokenExchangePath = "/v1/sign-access-token"

var _ TokenExchangeClient = &TokenExchangeClientImpl{}

type tokenExchangeClientImpl struct {
	cache   cache.Cache
	cfg     Config
	client  HTTPRequestDoer
	singlef singleflight.Group
}

func newClient(cfg Config) (*tokenExchangeClientImpl, error) {
	client := &tokenExchangeClientImpl{
		client: nil,
		cache: cache.NewLocalCache(cache.Config{
			Expiry:          tokenCacheTTL,
			CleanupInterval: 1 * time.Minute,
		}),
		cfg:     cfg,
		singlef: singleflight.Group{},
	}

	client.client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   4 * time.Second,
				KeepAlive: 15 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       30 * time.Second,
		},
		Timeout: 5 * time.Second,
	}

	return client, nil
}

func (c *tokenExchangeClientImpl) GetAccessToken(ctx context.Context, req AccessTokenRequest) (string, error) {
	key, err := tokenExchangeCacheKey(req)
	if err != nil {
		return "", fmt.Errorf("failed to generate cache key: %v", err)
	}
	if res, err := c.cache.Get(ctx, key); err == nil {
		token := string(res)
		return token, nil
	}

	resp, err, _ := c.singlef.Do(key, func() (interface{}, error) {
		target, err := url.JoinPath(c.cfg.AuthAPIURL, tokenExchangePath)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(key))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.cfg.CAP)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		res, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}

		defer res.Body.Close()

		response := tokenExchangeResponse{}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, err
		}

		if res.StatusCode != http.StatusOK || response.Status != "success" {
			return nil, fmt.Errorf("status code: %d, error: %s", res.StatusCode, response.Error)
		}

		return response, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to fetch access token: %v", err)
	}

	response, ok := resp.(tokenExchangeResponse)
	if !ok {
		return "", fmt.Errorf("unexpected response type")
	}

	c.cacheValue(ctx, response.Data.Token, key)

	return response.Data.Token, nil
}

func tokenExchangeCacheKey(query AccessTokenRequest) (string, error) {
	data, err := json.Marshal(query)
	return string(data), err
}

func (c *tokenExchangeClientImpl) cacheValue(ctx context.Context, token string, key string) error {
	return c.cache.Set(ctx, key, []byte(token), cache.DefaultExpiration)
}
