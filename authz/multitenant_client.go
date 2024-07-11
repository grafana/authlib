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

// TODO (gamab): Add caching
// TODO (gamab): Logs
// TODO (gamab): Traces
// TODO (gamab): AccessToken in outgoing context
// TODO (gamab): Make access token claims optional for dev purposes

var (
	ErrMissingConfig  = errors.New("missing config")
	ErrMissingAction  = status.Errorf(codes.InvalidArgument, "missing action")
	ErrMissingCaller  = status.Errorf(codes.Unauthenticated, "missing caller")
	ErrReadPermission = status.Errorf(codes.PermissionDenied, "read permission failed")
)

type CheckRequest struct {
	Caller     authn.CallerAuthInfo
	StackID    int64
	Action     string
	Resources  *Resource
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
	if req.Caller.AccessTokenClaims.Rest.DelegatedPermissions == nil {
		return false, nil
	}
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

	// Instantiate a new context for the request
	outCtx := NewOutgoingContext(ctx)

	readReq := &authzv1.ReadRequest{
		StackId: req.StackID,
		Action:  req.Action,
		Subject: req.Caller.IDTokenClaims.Subject,
	}

	// Query the authz service
	resp, err := c.clientV1.Read(outCtx, readReq)
	if err != nil {
		return false, ErrReadPermission
	}

	objs := []string{}
	for _, o := range resp.Data {
		objs = append(objs, o.Object)
	}

	// FIXME (gamab): Read does not return nil currently
	if req.Resources == nil {
		// resp.Data is not nil => the user has the requested action (with or without resources)
		return resp.Data != nil, nil
	}

	// TODO (gamab) Implement the checker

	// checker := compileChecker(objs, req.Object.Kind, req.Parent.Kind)
	// return checker(req.Object, req.Parent), nil
	return false, nil
}

func NewOutgoingContext(ctx context.Context) context.Context {
	out, cancel := context.WithCancel(context.Background())

	go func() {
		<-ctx.Done()
		cancel()
	}()

	return out
}

func ReadCacheKey(stackID int64, subject, action string) string {
	return fmt.Sprintf("read-%d-%s-%s", stackID, subject, action)
}

func (c *LegacyClientImpl) cacheReadResult(ctx context.Context, scopes []string, key string) error {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(scopes)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}
