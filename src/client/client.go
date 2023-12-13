package client

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/rbac-client-poc/src/cache"
	"github.com/grafana/rbac-client-poc/src/models"
)

var _ RBACClient = &RBACClientImpl{}

var (
	ErrInvalidQuery     = errors.New("invalid query")
	ErrInvalidToken     = errors.New("invalid token: cannot query server")
	ErrInvalidResponse  = errors.New("invalid response from server")
	ErrUnexpectedStatus = errors.New("unexpected response status")

	TimeNow  = time.Now
	CacheExp = 5 * time.Minute

	searchPath = "/api/access-control/user/%d/permissions/search"
)

type ClientCfg struct {
	Timeout    time.Duration
	GrafanaURL string
	Token      string
}

type SearchQuery struct {
	ActionPrefix string `json:"actionPrefix"`
	Action       string `json:"action"`
	Scope        string `json:"scope"`
	UserID       int64  `json:"userID"`
}

func searchCacheKey(query SearchQuery) string {
	// TODO : safe to ignore the error completely?
	data, _ := json.Marshal(query)
	return string(data)
}

type RBACClient interface {
	SearchUserPermissions(ctx context.Context, query SearchQuery) (models.Permissions, error)
}

func NewRBACClient(cfg ClientCfg, cache cache.Cache) *RBACClientImpl {
	return &RBACClientImpl{
		singlef: singleflight.Group{},
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		cache:  cache,
		cfg:    cfg,
		logger: log.NewJSONLogger(log.NewSyncWriter(os.Stdout)),
	}
}

type RBACClientImpl struct {
	singlef singleflight.Group
	client  *http.Client
	cache   cache.Cache
	cfg     ClientCfg
	logger  log.Logger
}

func validateQuery(query SearchQuery) error {
	if query.UserID <= 0 {
		return fmt.Errorf("%w: %v", ErrInvalidQuery, "userID must be strictly positive")
	}
	if query.Action == "" && query.ActionPrefix == "" {
		return fmt.Errorf("%w: %v", ErrInvalidQuery, "Action filter required")
	}
	return nil
}

// SearchUserPermissions implements RBACClient.
func (c *RBACClientImpl) SearchUserPermissions(ctx context.Context, query SearchQuery) (models.Permissions, error) {
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
		perms := models.Permissions{}
		err := gob.NewDecoder(r).Decode(&perms)
		if err != nil {
			level.Warn(c.logger).Log("could not decode data from cache", "error", err)
		} else {
			level.Debug(c.logger).Log("retrieved permissions from cache", "key", key)
			return perms, nil
		}
	}

	res, err, _ := c.singlef.Do(key, func() (interface{}, error) {
		url := c.cfg.GrafanaURL + fmt.Sprintf(searchPath, query.UserID)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(key))
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

		if res.StatusCode == http.StatusUnauthorized {
			return nil, ErrInvalidToken
		}

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%w: %s", ErrUnexpectedStatus, res.Status)
		}

		response := models.Permissions{}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidResponse, err)
		}
		return response, nil
	})

	if err != nil {
		level.Error(c.logger).Log("msg", "error sending request to Grafana API", "err", err)
		return nil, err
	}

	perms := res.(models.Permissions)
	c.cacheNoFail(ctx, perms, key)

	return perms, nil
}

func (c *RBACClientImpl) cacheNoFail(ctx context.Context, perms models.Permissions, key string) {
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
