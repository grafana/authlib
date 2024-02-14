package authz

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

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/internal/cache"
)

var _ Client = &ClientImpl{}

var (
	ErrInvalidQuery     = errors.New("invalid query")
	ErrInvalidIDToken   = errors.New("invalid id token: cannot extract namespaceID")
	ErrInvalidToken     = errors.New("invalid token: cannot query server")
	ErrInvalidResponse  = errors.New("invalid response from server")
	ErrUnexpectedStatus = errors.New("unexpected response status")

	TimeNow  = time.Now
	CacheExp = 5 * time.Minute

	searchPath = "/api/access-control/users/permissions/search"
)

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HTTPRequestDoer) ClientOption {
	return func(c *ClientImpl) error {
		c.client = doer

		return nil
	}
}

// WithCache allows overriding the default cache, which is a local cache.
func WithCache(cache cache.Cache) ClientOption {
	return func(c *ClientImpl) error {
		c.cache = cache

		return nil
	}
}

func NewClient(cfg Config, opts ...ClientOption) (*ClientImpl, error) {
	client := &ClientImpl{
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
		client.cache = cache.NewLocalCache(cache.Config{
			Expiry:          5 * time.Minute,
			CleanupInterval: 1 * time.Minute,
		})
	}

	client.verifier = authn.NewVerifier[CustomClaims](authn.IDVerifierConfig{SigningKeyURL: cfg.JWKsURL})

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

type ClientImpl struct {
	cache    cache.Cache
	cfg      Config
	client   HTTPRequestDoer
	logger   log.Logger
	verifier authn.Verifier[CustomClaims]
	singlef  singleflight.Group
}

func searchCacheKey(query SearchQuery) string {
	// TODO : safe to ignore the error completely?
	data, _ := json.Marshal(query)
	return string(data)
}

func (query *SearchQuery) processResource() {
	if query.Resource != nil {
		query.Scope = query.Resource.Scope()
	}
}

// processIDToken verifies the id token is legit and extracts its subject in the query.NamespaceID.
func (query *SearchQuery) processIDToken(c *ClientImpl) error {
	if query.IdToken != "" {
		claims, err := c.verifier.Verify(context.Background(), query.IdToken)
		if err != nil {
			return fmt.Errorf("%v: %w", ErrInvalidIDToken, err)
		}
		if claims.Subject == "" {
			return fmt.Errorf("%v: %w", ErrInvalidIDToken, errors.New("missing subject (namespaceID) in id token"))
		}
		query.NamespaceID = claims.Subject
	}
	return nil
}

// validateQuery checks if the query is valid.
func (query *SearchQuery) validateQuery() error {
	// Validate inputs
	if (query.ActionPrefix != "") && (query.Action != "") {
		return fmt.Errorf("%w: %v", ErrInvalidQuery, "'action' and 'actionPrefix' are mutually exclusive")
	}
	if query.NamespaceID == "" && query.ActionPrefix == "" && query.Action == "" {
		return fmt.Errorf("%w: %v", ErrInvalidQuery, "at least one search option must be provided")
	}
	return nil
}

// Search returns the permissions for the given query.
func (c *ClientImpl) Search(ctx context.Context, query SearchQuery) (*SearchResponse, error) {
	// set scope if resource is provided
	query.processResource()

	// set namespaceID if id token is provided
	if err := query.processIDToken(c); err != nil {
		level.Error(c.logger).Log("msg", "error processing id token", "err", err)
		return nil, err
	}

	// validate query
	if err := query.validateQuery(); err != nil {
		level.Error(c.logger).Log("invalid query", "error", err)
		return nil, err
	}

	key := searchCacheKey(query)

	item, err := c.cache.Get(ctx, key)
	if err != nil && !errors.Is(err, cache.ErrNotFound) {
		level.Warn(c.logger).Log("could not retrieve from cache", "error", err)
	}

	if err == nil {
		perms := PermissionsByID{}
		err := gob.NewDecoder(bytes.NewReader(item)).Decode(&perms)
		if err != nil {
			level.Warn(c.logger).Log("could not decode data from cache", "error", err)
		} else {
			level.Debug(c.logger).Log("retrieved permissions from cache", "key", key)
			return &SearchResponse{Data: &perms}, nil
		}
	}

	res, err, _ := c.singlef.Do(key, func() (interface{}, error) {
		v, _ := goquery.Values(query)
		url := strings.TrimRight(c.cfg.GrafanaURL, "/") + searchPath + "?" + v.Encode()
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

		response := PermissionsByID{}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidResponse, err)
		}
		return response, nil
	})

	if err != nil {
		level.Error(c.logger).Log("msg", "error sending request to Grafana API", "err", err)
		return nil, err
	}

	perms := res.(PermissionsByID)
	c.cacheNoFail(ctx, perms, key)

	return &SearchResponse{Data: &perms}, nil
}

func (c *ClientImpl) cacheNoFail(ctx context.Context, perms PermissionsByID, key string) {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(perms)
	if err != nil {
		level.Warn(c.logger).Log("msg", "error encoding result for cache", "err", err)
		return
	}

	if err = c.cache.Set(ctx, key, buf.Bytes(), CacheExp); err != nil {
		level.Warn(c.logger).Log("msg", "error caching result", "key", key, "err", err)
	}
}
