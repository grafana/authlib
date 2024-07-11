package authz

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"time"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TODO (gamab): Logs
// TODO (gamab): Traces
// TODO (gamab): AccessToken in outgoing context
// TODO (gamab): Make access token claims optional for dev purposes

var (
	ErrMissingConfig  = errors.New("missing config")
	ErrMissingAction  = status.Errorf(codes.InvalidArgument, "missing action")
	ErrMissingCaller  = status.Errorf(codes.Unauthenticated, "missing caller")
	ErrReadPermission = status.Errorf(codes.PermissionDenied, "read permission failed")
	ErrCaching        = status.Errorf(codes.Internal, "caching failed")
)

type CheckRequest struct {
	Caller     authn.CallerAuthInfo
	StackID    int64
	Action     string
	Resource   *Resource
	Contextual []Resource
}

type MultiTenantClient interface {
	Check(ctx context.Context, req *CheckRequest) (bool, error)
}

type MultiTenantClientConfig struct {
	remoteAddress string
}

var _ MultiTenantClient = (*LegacyClientImpl)(nil)

type LegacyClientImpl struct {
	authCfg  *MultiTenantClientConfig
	clientV1 authzv1.AuthzServiceClient
	cache    cache.Cache
}

func NewLegacyClient(cfg *MultiTenantClientConfig) (*LegacyClientImpl, error) {
	if cfg == nil {
		return nil, ErrMissingConfig
	}
	if cfg.remoteAddress == "" {
		return nil, fmt.Errorf("missing remote address: %w", ErrMissingConfig)
	}

	return &LegacyClientImpl{
		authCfg: cfg,
		cache: cache.NewLocalCache(cache.Config{
			Expiry:          cacheExp,
			CleanupInterval: 1 * time.Minute,
		}),
	}, nil
}

func (r *CheckRequest) Validate() error {
	if r.Action == "" {
		return ErrMissingAction
	}
	if r.Caller.AccessTokenClaims.Subject == "" {
		return ErrMissingCaller
	}
	return nil
}

func (c *LegacyClientImpl) Check(ctx context.Context, req *CheckRequest) (bool, error) {
	// No user => check on the service permissions
	if req.Caller.IDTokenClaims == nil {
		perms := req.Caller.AccessTokenClaims.Rest.Permissions
		for _, p := range perms {
			if p == req.Action {
				return true, nil
			}
		}
		return false, nil
	}

	// Make sure the service is allowed to perform the requested action
	serviceIsAllowedAction := false
	for _, p := range req.Caller.AccessTokenClaims.Rest.DelegatedPermissions {
		if p == req.Action {
			serviceIsAllowedAction = true
			break
		}
	}
	if !serviceIsAllowedAction {
		return false, nil
	}

	res, err := c.retrievePermissions(ctx, req.StackID, req.Caller.AccessTokenClaims.Subject, req.Action)
	if err != nil {
		return false, err
	}

	// No permissions found
	if !res.Found {
		return false, nil
	}

	// Action check only
	if req.Resource == nil {
		return true, nil
	}

	// Check if the resource is allowed
	check := res.Check(append(req.Contextual, *req.Resource)...)
	return check, nil
}

func (c *LegacyClientImpl) retrievePermissions(ctx context.Context, stackID int64, subject, action string) (*ReadResult, error) {
	key := ReadCacheKey(stackID, subject, action)
	res, err := c.getCacheReadResult(ctx, key)
	if err == nil {
		return res, nil
	}
	if !errors.Is(err, cache.ErrNotFound) {
		return nil, fmt.Errorf("%w: %w", ErrCaching, err)
	}

	// Instantiate a new context for the request
	outCtx := NewOutgoingContext(ctx)

	readReq := &authzv1.ReadRequest{
		StackId: stackID,
		Action:  action,
		Subject: subject,
	}

	// Query the authz service
	resp, err := c.clientV1.Read(outCtx, readReq)
	if err != nil {
		return nil, ErrReadPermission
	}

	res = NewReadResult(resp)

	// Cache the result
	if err := c.cacheReadResult(ctx, key, res); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCaching, err)
	}

	return res, nil
}

func NewOutgoingContext(ctx context.Context) context.Context {
	out, cancel := context.WithCancel(context.Background())

	go func() {
		<-ctx.Done()
		cancel()
	}()

	return out
}

// -----
// RESULT
// -----

type ReadResult struct {
	// Whether the permissions were found
	Found bool
	// All the scopes the user has access to
	Scopes map[string]bool
	// Wildcard per kinds
	Wildcard map[string]bool
}

func NewReadResult(resp *authzv1.ReadResponse) *ReadResult {
	if resp == nil || !resp.Found {
		return &ReadResult{Found: false}
	}

	res := &ReadResult{
		Found:    true,
		Scopes:   make(map[string]bool, len(resp.Data)),
		Wildcard: make(map[string]bool, 2),
	}
	for _, o := range resp.Data {
		kind, _, id := splitScope(o.Object)
		if id == "*" {
			res.Wildcard[kind] = true
		} else {
			res.Scopes[o.Object] = true
		}
	}
	return res
}

func (r *ReadResult) Check(resources ...Resource) bool {
	// the user has no permissions
	if !r.Found {
		return false
	}

	// it's an action check only
	if len(resources) == 0 {
		return true
	}

	// the user has no permissions
	if len(r.Scopes) == 0 && len(r.Wildcard) == 0 {
		return false
	}

	// the user has access to all resources
	if r.Wildcard["*"] {
		return true
	}

	// the user has access to the requested resources
	for _, res := range resources {
		if r.Wildcard[res.Kind] || r.Scopes[res.Scope()] {
			return true
		}
	}
	return false
}

// -----
// CACHE
// -----

func ReadCacheKey(stackID int64, subject, action string) string {
	return fmt.Sprintf("read-%d-%s-%s", stackID, subject, action)
}

func (c *LegacyClientImpl) cacheReadResult(ctx context.Context, key string, res *ReadResult) error {
	if res == nil {
		return nil
	}

	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(*res)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}

func (c *LegacyClientImpl) getCacheReadResult(ctx context.Context, key string) (*ReadResult, error) {
	data, err := c.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var res ReadResult
	err = gob.NewDecoder(bytes.NewReader(data)).Decode(&res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
