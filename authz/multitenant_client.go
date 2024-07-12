package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TODO (gamab): Caching
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
	if r.Caller.AccessTokenClaims.Claims == nil {
		return ErrMissingCaller
	}
	return nil
}

func (c *LegacyClientImpl) Check(ctx context.Context, req *CheckRequest) (bool, error) {
	if err := req.Validate(); err != nil {
		return false, err
	}

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

	res, err := c.retrievePermissions(ctx, req.StackID, req.Caller.IDTokenClaims.Subject, req.Action)
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

	// Check if the user has access to any of the requested resources
	return res.Check(append(req.Contextual, *req.Resource)...), nil
}

func (c *LegacyClientImpl) retrievePermissions(ctx context.Context, stackID int64, subject, action string) (*controller, error) {
	// TOD (gamab): Check cache

	// Instantiate a new context for the request
	outCtx := newOutgoingContext(ctx)

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

	res := newController(resp)

	// TODO (gamab) cache the result
	return res, nil
}

// newOutgoingContext creates a new context that will be canceled when the input context is canceled.
func newOutgoingContext(ctx context.Context) context.Context {
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

type controller struct {
	// Whether the requested action was found in the users' permissions
	Found bool
	// All the scopes the user has access to for the requested action
	Scopes map[string]bool
	// Wildcard per kinds
	Wildcard map[string]bool
}

func newController(resp *authzv1.ReadResponse) *controller {
	if resp == nil || !resp.Found {
		return &controller{Found: false}
	}

	res := &controller{
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

func (r *controller) Check(resources ...Resource) bool {
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
