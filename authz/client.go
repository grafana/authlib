package authz

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	goquery "github.com/google/go-querystring/query"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/internal/httpclient"
)

var _ client = &clientImpl{}

var (
	ErrInvalidQuery       = errors.New("invalid query")
	ErrUnsupported        = errors.New("unsupported query")
	ErrInvalidIDToken     = errors.New("invalid id token: cannot extract namespaced ID")
	ErrInvalidToken       = errors.New("invalid token: cannot query server")
	ErrInvalidResponse    = errors.New("invalid response from server")
	ErrUnexpectedStatus   = errors.New("unexpected response status")
	ErrTooManyPermissions = errors.New("unexpected number of permissions returned by the server")
)

const (
	cacheExp   = 5 * time.Minute
	searchPath = "/api/access-control/users/permissions/search"
)

func withTokenProvider(provider TokenProviderFunc) clientOption {
	return func(c *clientImpl) error {
		c.getToken = provider

		return nil
	}
}

// withHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func withHTTPClient(doer HTTPRequestDoer) clientOption {
	return func(c *clientImpl) error {
		c.client = doer

		return nil
	}
}

// withCache allows overriding the default cache, which is a local cache.
func withCache(cache cache.Cache) clientOption {
	return func(c *clientImpl) error {
		c.cache = cache

		return nil
	}
}

func newClient(cfg Config, opts ...clientOption) (*clientImpl, error) {
	client := &clientImpl{
		cache:   nil,
		cfg:     cfg,
		client:  nil,
		singlef: singleflight.Group{},
	}

	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	if client.cache == nil {
		client.cache = cache.NewLocalCache(cache.Config{
			Expiry:          cacheExp,
			CleanupInterval: 1 * time.Minute,
		})
	}

	// create httpClient, if not already present
	if client.client == nil {
		client.client = httpclient.New()
	}

	if client.getToken == nil {
		client.getToken = func(_ context.Context) (string, error) {
			return cfg.Token, nil
		}
	}

	return client, nil
}

type clientImpl struct {
	cache    cache.Cache
	cfg      Config
	client   HTTPRequestDoer
	singlef  singleflight.Group
	getToken TokenProviderFunc
}

func searchCacheKey(query searchQuery) string {
	// TODO : safe to ignore the error completely?
	data, _ := json.Marshal(query)
	return string(data)
}

func (query *searchQuery) processResource() {
	if query.Resource != nil {
		query.Scope = query.Resource.Scope()
	}
}

// validateQuery checks if the query is valid.
func (query *searchQuery) validateQuery() error {
	// Validate inputs
	if (query.ActionPrefix != "") && (query.Action != "") {
		return fmt.Errorf("%w: %v", ErrInvalidQuery,
			"'action' and 'actionPrefix' are mutually exclusive")
	}
	if query.NamespacedID == "" && query.ActionPrefix == "" && query.Action == "" {
		return fmt.Errorf("%w: %v", ErrInvalidQuery,
			"at least one search option must be provided")
	}
	return nil
}

// Search returns the permissions for the given query.
func (c *clientImpl) Search(ctx context.Context, query searchQuery) (*searchResponse, error) {
	// set scope if resource is provided
	query.processResource()

	// validate query
	if err := query.validateQuery(); err != nil {
		return nil, err
	}

	key := searchCacheKey(query)

	item, err := c.cache.Get(ctx, key)
	if err != nil && !errors.Is(err, cache.ErrNotFound) {
		return nil, err
	}

	if err == nil {
		perms := permissions{}
		err := gob.NewDecoder(bytes.NewReader(item)).Decode(&perms)
		if err != nil {
			return nil, fmt.Errorf("failed to decode cache entry: %w", err)
		} else {
			return &searchResponse{Data: &perms}, nil
		}
	}

	res, err, _ := c.singlef.Do(key, func() (interface{}, error) {
		v, _ := goquery.Values(query)
		url := strings.TrimRight(c.cfg.APIURL, "/") + searchPath + "?" + v.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, strings.NewReader(key))
		if err != nil {
			return nil, err
		}

		token, err := c.getToken(ctx)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+token)
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

		response := permissionsByID{}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidResponse, err)
		}

		extract := []permissions{}
		if len(response) > 1 {
			return nil, fmt.Errorf("%w: response contains more than 1 element, length %d", ErrTooManyPermissions, len(response))
		}
		for _, perms := range response {
			extract = append(extract, perms)
		}
		return extract, nil
	})

	if err != nil {
		return nil, err
	}

	perms := res.(permissions)
	if err := c.cacheValue(ctx, perms, key); err != nil {
		return nil, fmt.Errorf("failed to cache response: %w", err)
	}

	return &searchResponse{Data: &perms}, nil
}

func (c *clientImpl) cacheValue(ctx context.Context, perms permissions, key string) error {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(perms)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}
