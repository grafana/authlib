package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v3/jwt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
)

// Set cache TTL one minute shorter than token expiry
const tokenCacheTTL = 9 * time.Minute
const tokenExchangePath = "/v1/sign-access-token"

type TokenExchangeClient interface {
	// GetAccessToken returns a short-lived access Token for the given claims.
	GetAccessToken(ctx context.Context, req AccessTokenRequest) (string, error)
}

type Config struct {
	CAP        string `json:"cloudAccessPolicy"` // cloud access policy token used for authorising the request
	AuthAPIURL string `json:"authAPIURL"`        // URL of the auth server
}

func NewTokenExchangeClient(cfg Config) (*tokenExchangeClientImpl, error) {
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

type tokenExchangeClientImpl struct {
	cache   cache.Cache
	cfg     Config
	client  *http.Client
	singlef singleflight.Group
}

type RealmList []Realm

type Realm struct {
	Type       string `json:"type"`       // org or stack
	Identifier string `json:"identifier"` // org id or stack id
}

type AccessTokenRequest struct {
	Claims jwt.Claims // claims to be included in the access token
	Extra  map[string]any
	Realms RealmList // A JSON-encoded array of objects containing the realms the request should be restricted to.
	OrgID  int64     // ID of the org the request should be restricted to.
}

type Data struct {
	Token string `json:"token"`
}

type tokenExchangeResponse struct {
	Data   Data   `json:"data"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

func (c *tokenExchangeClientImpl) GetAccessToken(ctx context.Context, tokenReq AccessTokenRequest) (string, error) {
	key, err := tokenExchangeCacheKey(tokenReq)
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
		if len(tokenReq.Realms) > 0 {
			realms, err := json.Marshal(tokenReq.Realms)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal realms: %v", err)
			}
			req.Header.Set("X-Realms", string(realms))
		}
		if tokenReq.OrgID != 0 {
			req.Header.Set("X-Org-ID", strconv.Itoa(int(tokenReq.OrgID)))
		}

		res, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch access token: %v", err)
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
