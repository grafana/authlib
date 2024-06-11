package authz

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
)

var _ client = &grpcClientImpl{}

func newGRPCClient(cfg Config, opts ...grpcClientOption) (*grpcClientImpl, error) {
	client := &grpcClientImpl{
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

	// Default client
	if client.client == nil {
		grpcClient, err := grpc.NewClient(cfg.APIURL)
		if err != nil {
			return nil, err
		}
		client.client = authzv1.NewAuthzServiceClient(grpcClient)
	}

	// Default token provider
	if client.getToken == nil {
		client.getToken = func(ctx context.Context) (string, error) {
			return cfg.Token, nil
		}
	}

	if client.cfg.StackID <= 0 {
		return nil, fmt.Errorf("stack id is required")
	}

	return client, nil
}

type grpcClientImpl struct {
	cache    cache.Cache
	cfg      Config
	client   authzv1.AuthzServiceClient
	singlef  singleflight.Group
	getToken TokenProviderFunc
}

// Search returns the permissions for the given query.
func (c *grpcClientImpl) Search(ctx context.Context, query searchQuery) (*searchResponse, error) {
	// Remove scope in the grpc client: unsupported
	// TODO: I worry about bloat in the cache, but I think it's fine for now
	scope := query.Scope
	query.Scope = ""

	if query.ActionPrefix != "" {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, "'actionPrefix' is not supported in grpc client")
	}

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
			// Only return the permissions for the requested scope
			ret := applyScope(perms, scope)
			return &searchResponse{Data: &ret}, nil
		}
	}

	res, err, _ := c.singlef.Do(key, func() (interface{}, error) {
		token, err := c.getToken(ctx)
		if err != nil {
			return nil, err
		}

		ctx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", token))

		res, err := c.client.Read(ctx, &authzv1.ReadRequest{
			Subject: query.NamespacedID.String(),
			Action:  query.Action,
			StackId: c.cfg.StackID,
		})
		if err != nil {
			return nil, err
		}

		ret := permissions{}
		for _, o := range res.Data {
			ret[query.Action] = append(ret[query.Action], o.Object)
		}

		return ret, nil
	})
	if err != nil {
		return nil, err
	}

	perms := res.(permissions)
	if err := c.cacheValue(ctx, perms, key); err != nil {
		return nil, fmt.Errorf("failed to cache response: %w", err)
	}

	// Only return the permissions for the requested scope
	ret := applyScope(perms, scope)
	return &searchResponse{Data: &ret}, nil
}

func applyScope(perms permissions, scope string) permissions {
	if scope == "" {
		return perms
	}
	ret := permissions{}
	for action, scopes := range perms {
		for _, v := range scopes {
			if scope != "" && v == scope {
				ret[action] = append(ret[action], v)
			}
		}
	}
	return ret
}

func (c *grpcClientImpl) cacheValue(ctx context.Context, perms permissions, key string) error {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(perms)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}
