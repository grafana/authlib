package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	goquery "github.com/google/go-querystring/query"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/rbac-client-poc/pkg/ac/cache"
	"github.com/grafana/rbac-client-poc/pkg/ac/models"
)

var _ RBACClient = &RBACClientImpl{}

var (
	ErrInvalidQuery     = errors.New("invalid query")
	ErrInvalidToken     = errors.New("invalid token: cannot query server")
	ErrInvalidResponse  = errors.New("invalid response from server")
	ErrUnexpectedStatus = errors.New("unexpected response status")

	TimeNow  = time.Now
	CacheExp = 5 * time.Minute

	searchPath = "/api/access-control/users/permissions/search"
)

type ClientCfg struct {
	GrafanaURL string
	Token      string
}

type SearchQuery struct {
	ActionPrefix string `json:"actionPrefix,omitempty" url:"actionPrefix,omitempty"`
	Action       string `json:"action,omitempty" url:"action,omitempty"`
	Scope        string `json:"scope,omitempty" url:"scope,omitempty"`
	UserID       int64  `json:"userId" url:"userId,omitempty"`
	UserLogin    string `json:"userLogin" url:"userLogin,omitempty"`
}

func searchCacheKey(query SearchQuery) string {
	// TODO : safe to ignore the error completely?
	data, _ := json.Marshal(query)
	return string(data)
}

type RBACClient interface {
	SearchUserPermissions(ctx context.Context, query SearchQuery) (models.UsersPermissions, error)
}

// ClientOption allows setting custom parameters during construction.
type ClientOption func(*RBACClientImpl) error

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HTTPRequestDoer) ClientOption {
	return func(c *RBACClientImpl) error {
		c.client = doer

		return nil
	}
}

func WithCache(cache cache.Cache) ClientOption {
	return func(c *RBACClientImpl) error {
		c.cache = cache

		return nil
	}
}

func NewRBACClient(cfg ClientCfg, opts ...ClientOption) (*RBACClientImpl, error) {
	client := &RBACClientImpl{
		singlef: singleflight.Group{},
		client:  nil,
		cache:   nil,
		cfg:     cfg,
		logger:  log.NewJSONLogger(log.NewSyncWriter(os.Stdout)),
	}

	for _, opt := range opts {
		if err := opt(client); err != nil {
			_ = level.Error(client.logger).Log("msg", "error applying option", "err", err)
		}
	}

	if client.cache == nil {
		client.cache = cache.NewLocalCache()
	}

	// create httpClient, if not already present
	if client.client == nil {
		client.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Renegotiation: tls.RenegotiateFreelyAsClient,
				},
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
			Timeout: 20 * time.Second,
		}
	}

	return client, nil
}

type RBACClientImpl struct {
	singlef singleflight.Group
	client  HTTPRequestDoer
	cache   cache.Cache
	cfg     ClientCfg
	logger  log.Logger
}

func validateQuery(query SearchQuery) error {
	// Validate inputs
	if (query.ActionPrefix != "") && (query.Action != "") {
		return fmt.Errorf("%w: %v", ErrInvalidQuery, "'action' and 'actionPrefix' are mutually exclusive")
	}
	if (query.UserLogin != "") && (query.UserID > 0) {
		return fmt.Errorf("%w: %v", ErrInvalidQuery, "'userId' and 'userLogin' are mutually exclusive")
	}
	if query.UserID <= 0 && query.UserLogin == "" &&
		query.ActionPrefix == "" && query.Action == "" {
		return fmt.Errorf("%w: %v", ErrInvalidQuery, "at least one search option must be provided")
	}
	return nil
}

// SearchUserPermissions implements RBACClient.
func (c *RBACClientImpl) SearchUserPermissions(ctx context.Context, query SearchQuery) (models.UsersPermissions, error) {
	if err := validateQuery(query); err != nil {
		level.Error(c.logger).Log("invalid query", "error", err)
		return nil, err
	}

	key := searchCacheKey(query)

	r, ok, err := c.cache.Get(ctx, key)
	if err != nil {
		level.Warn(c.logger).Log("could not retrieve from cache", "error", err)
	}

	if ok {
		perms := models.UsersPermissions{}
		err := gob.NewDecoder(r).Decode(&perms)
		if err != nil {
			level.Warn(c.logger).Log("could not decode data from cache", "error", err)
		} else {
			level.Debug(c.logger).Log("retrieved permissions from cache", "key", key)
			return perms, nil
		}
	}

	res, err, _ := c.singlef.Do(key, func() (interface{}, error) {
		v, _ := goquery.Values(query)
		url := c.cfg.GrafanaURL + searchPath + "?" + v.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, strings.NewReader(key))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		res, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}

		defer res.Body.Close()

		if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
			return nil, ErrInvalidToken
		}

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%w: %s", ErrUnexpectedStatus, res.Status)
		}

		response := models.UsersPermissions{}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidResponse, err)
		}
		return response, nil
	})

	if err != nil {
		level.Error(c.logger).Log("msg", "error sending request to Grafana API", "err", err)
		return nil, err
	}

	perms := res.(models.UsersPermissions)
	c.cacheNoFail(ctx, perms, key)

	return perms, nil
}

func (c *RBACClientImpl) cacheNoFail(ctx context.Context, perms models.UsersPermissions, key string) {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(perms)
	if err != nil {
		level.Warn(c.logger).Log("msg", "error encoding result for cache", "err", err)
		return
	}

	if err = c.cache.Set(ctx, key, CacheExp, bytes.NewReader(buf.Bytes())); err != nil {
		level.Warn(c.logger).Log("msg", "error caching result", "key", key, "err", err)
	}
}
