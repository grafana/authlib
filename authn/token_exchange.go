package authn

import (
	"context"
	"encoding/base64"
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

const cacheBuffer = 15 * time.Second
const tokenExchangePath = "/v1/sign-access-token"

type TokenExchangeClient interface {
	// GetAccessToken returns a short-lived access Token for the given claims.
	GetAccessToken(ctx context.Context, req TokenExchangeRequest) (string, error)
}

type TokenExchangeConfig struct {
	CAP           string // cloud access policy token used for authorising the request
	usesSystemCAP bool
	AuthAPIURL    string // URL of the auth server
}

func NewTokenExchangeClient(cfg TokenExchangeConfig) (*tokenExchangeClientImpl, error) {
	if cfg.CAP == "" {
		return nil, fmt.Errorf("cloud access policy (CAP) is required")
	}
	usesSystemCAP, err := isSystemWideCAP(cfg.CAP)
	if err != nil {
		return nil, fmt.Errorf("invalid CAP: %v", err)
	}
	cfg.usesSystemCAP = usesSystemCAP

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

// isSystemWideCAP checks if the given CAP is a system-wide CAP by looking at the org ID in the CAP.
func isSystemWideCAP(cap string) (bool, error) {
	capParts := strings.Split(cap, "_")
	// strip CAP prefix
	strippedCAP := capParts[len(capParts)-1]
	decodedCAP, err := base64.StdEncoding.DecodeString(strippedCAP)
	if err != nil {
		return false, fmt.Errorf("failed to decode CAP: %v", err)
	}
	type capToken struct {
		OrgID string `json:"o"`
	}
	var capData capToken
	if err := json.Unmarshal(decodedCAP, &capData); err != nil {
		return false, fmt.Errorf("failed to unmarshal CAP: %v", err)
	}
	return capData.OrgID == "0", nil
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

type TokenExchangeData struct {
	Token string `json:"token"`
}

type tokenExchangeResponse struct {
	Data   TokenExchangeData `json:"data"`
	Status string            `json:"status"`
	Error  string            `json:"error"`
}

func (c *tokenExchangeClientImpl) GetAccessToken(ctx context.Context, tokenReq TokenExchangeRequest) (string, error) {
	if c.cfg.usesSystemCAP && (tokenReq.OrgID == 0 || len(tokenReq.Realms) == 0) {
		return "", fmt.Errorf("org ID and realms must be specified when using system-wide CAP")
	}

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
