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
	goquery "github.com/google/go-querystring/query"
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

	searchPath = "/api/access-control/users/permissions/search"
)

type ClientCfg struct {
	Timeout    time.Duration
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
