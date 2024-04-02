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
	"strings"
	"time"

	goquery "github.com/google/go-querystring/query"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/cache"
)

var _ client = &clientImpl{}

var (
	ErrInvalidQuery     = errors.New("invalid query")
	ErrInvalidIDToken   = errors.New("invalid id token: cannot extract namespaced ID")
	ErrInvalidToken     = errors.New("invalid token: cannot query server")
	ErrInvalidResponse  = errors.New("invalid response from server")
	ErrUnexpectedStatus = errors.New("unexpected response status")
)

const (
	cacheExp   = 5 * time.Minute
	searchPath = "/api/access-control/users/permissions/search"
)

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
		singlef: singleflight.Group{},
		client:  nil,
		cache:   nil,
		cfg:     cfg,
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

	client.verifier = authn.NewVerifier[customClaims](authn.IDVerifierConfig{SigningKeysURL: cfg.JWKsURL})

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

type clientImpl struct {
	cache    cache.Cache
	cfg      Config
	client   HTTPRequestDoer
	verifier authn.Verifier[customClaims]
	singlef  singleflight.Group
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

// processIDToken verifies the id token is legit and extracts its subject in the query.NamespacedID.
func (query *searchQuery) processIDToken(c *clientImpl) error {
	if query.IdToken != "" {
		claims, err := c.verifier.Verify(context.Background(), query.IdToken, authn.TypeIDToken)
		if err != nil {
			return fmt.Errorf("%v: %w", ErrInvalidIDToken, err)
		}
		if claims.Subject == "" {
			return fmt.Errorf("%v: %w", ErrInvalidIDToken, errors.New("missing subject (namespacedID) in id token"))
		}
		query.NamespacedID = claims.Subject
	}
	return nil
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

	// set namespaced ID if id token is provided
	if err := query.processIDToken(c); err != nil {
		return nil, err
	}

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
		perms := permissionsByID{}
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

		response := permissionsByID{}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidResponse, err)
		}
		return response, nil
	})

	if err != nil {
		return nil, err
	}

	perms := res.(permissionsByID)
	if err := c.cacheValue(ctx, perms, key); err != nil {
		return nil, fmt.Errorf("failed to cache response: %w", err)
	}

	return &searchResponse{Data: &perms}, nil
}

func (c *clientImpl) cacheValue(ctx context.Context, perms permissionsByID, key string) error {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(perms)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}
