package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
)

const cacheBuffer = 15 * time.Second
const tokenExchangePath = "/v1/sign-access-token"

type TokenExchangeClient interface {
	// GetAccessTokenOnBehalfOf exchanges a system-wide CAP token for a short-lived access token for the org or stack specified in the request.
	GetAccessTokenOnBehalfOf(ctx context.Context, req TokenExchangeRequest) (string, error)
	// GetAccessToken returns a short-lived access token for the org or stack that CAP token is for.
	GetAccessToken(ctx context.Context) (string, error)
}

type TokenExchangeConfig struct {
	CAPToken   string // cloud access policy token used for authorising the request
	AuthAPIURL string // URL of the auth server
}

func NewTokenExchangeClient(cfg TokenExchangeConfig) (*tokenExchangeClientImpl, error) {
	if cfg.CAPToken == "" {
		return nil, fmt.Errorf("cloud access policy (CAPToken) is required")
	}

	if cfg.AuthAPIURL == "" {
		return nil, fmt.Errorf("auth API URL is required")
	}

	client := &tokenExchangeClientImpl{
		client: nil,
		cache: cache.NewLocalCache(cache.Config{
			CleanupInterval: 5 * time.Minute,
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
	cfg     TokenExchangeConfig
	client  *http.Client
	singlef singleflight.Group
}

type Realm struct {
	Type       string `json:"type"`       // org or stack
	Identifier string `json:"identifier"` // org id or stack id
}

type TokenExchangeRequest struct {
	Realms []Realm // A JSON-encoded array of objects containing the realms the request should be restricted to.
	OrgID  int64   // ID of the org the request should be restricted to.
}

type tokenExchangeData struct {
	Token string `json:"token"`
}

type tokenExchangeResponse struct {
	Data   tokenExchangeData `json:"data"`
	Status string            `json:"status"`
	Error  string            `json:"error"`
}

func (c *tokenExchangeClientImpl) GetAccessTokenOnBehalfOf(ctx context.Context, tokenReq TokenExchangeRequest) (string, error) {
	if tokenReq.OrgID == 0 || len(tokenReq.Realms) == 0 {
		return "", fmt.Errorf("org ID and realms must be specified when fecthing access token on behalf of a user")
	}

	return c.getAccessToken(ctx, tokenReq)
}

func (c *tokenExchangeClientImpl) GetAccessToken(ctx context.Context) (string, error) {
	return c.getAccessToken(ctx, TokenExchangeRequest{})
}

func (c *tokenExchangeClientImpl) getAccessToken(ctx context.Context, tokenReq TokenExchangeRequest) (string, error) {
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

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader("{}"))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.cfg.CAPToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "authlib-client")
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

	if err := c.cacheValue(ctx, response.Data.Token, key); err != nil {
		return "", err
	}

	return response.Data.Token, nil
}

func tokenExchangeCacheKey(query TokenExchangeRequest) (string, error) {
	data, err := json.Marshal(query)
	return string(data), err
}

func (c *tokenExchangeClientImpl) cacheValue(ctx context.Context, token string, key string) error {
	// decode JWT token without verifying the signature to extract the expiry time
	var claims jwt.Claims
	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return fmt.Errorf("failed to parse token: %v", err)
	}
	err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return fmt.Errorf("failed to extract claims from the token: %v", err)
	}
	ttl := time.Until(claims.Expiry.Time()) - cacheBuffer

	return c.cache.Set(ctx, key, []byte(token), ttl)
}
