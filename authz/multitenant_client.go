package authz

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/claims"
)

var (
	ErrMissingConfig           = errors.New("missing config")
	ErrMissingRequestNamespace = errors.New("missing request namespace")
	ErrInvalidRequestNamespace = errors.New("invalid request namespace")
	ErrMissingRequestAttribute = errors.New("missing request attribute")
	ErrMissingRequestResource  = errors.New("missing request resource")
	ErrMissingRequestAction    = errors.New("missing request action")
	ErrMissingCaller           = errors.New("missing caller")
	ErrMissingSubject          = errors.New("missing subject")

	checkResponseDenied  = CheckResponse{Allowed: false}
	checkResponseAllowed = CheckResponse{Allowed: true}
)

type CheckRequest struct {
	// The namespace in which the request is made (e.g. "stacks-12")
	Namespace string
	// The requested action (e.g. "dashboards:read")
	Action string
	// ~Kind eg dashboards
	Resource string
	// Attribute used to identify the resource in the legacy RBAC system (e.g. uid).
	Attribute string
	// The specific resource
	// In grafana, this was historically called "UID", but in k8s, it is the name
	Name string
	// The Name of the parent folder of the resource
	Parent string
}

type CheckResponse struct {
	// Whether the caller is allowed to perform the requested action
	Allowed bool
}

// Client is the interface for the Grafana app-platform authorization client.
// This client can be used by Multi-tenant applications.
type Client interface {
	// Check verifies if the Caller has access to specific resources within a namespace.
	//
	// Caller represents the authentication information of the entity
	// initiating the request, which can be a service or a user.
	//
	// CheckRequest contains the details of the request, including the namespace, action, resource, parent.
	//
	// The method returns a CheckResponse containing weather the caller is authorized.
	// An error is returned if the authorization check cannot be completed,
	// for example, due to an unreachable authorization service.
	Check(ctx context.Context, caller claims.AuthInfo, req *CheckRequest) (CheckResponse, error)
}

type ClientConfig struct {
	// RemoteAddress is the address of the authz service. It should be in the format "host:port".
	RemoteAddress string

	// accessTokenAuthEnabled is a flag to enable access token authentication.
	// If disabled, no service authentication will be performed. Defaults to true.
	accessTokenAuthEnabled bool
}

var _ Client = (*LegacyClientImpl)(nil)

type LegacyClientOption func(*LegacyClientImpl)

type LegacyClientImpl struct {
	authCfg     *ClientConfig
	clientV1    authzv1.AuthzServiceClient
	cache       cache.Cache
	grpcConn    grpc.ClientConnInterface
	grpcOptions []grpc.DialOption
	tracer      trace.Tracer
}

type tracerProvider struct {
	trace.TracerProvider
	tracer trace.Tracer
}

func (tp *tracerProvider) Tracer(name string, options ...trace.TracerOption) trace.Tracer {
	return tp.tracer
}

// -----
// Options
// -----

func WithCacheLCOption(cache cache.Cache) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.cache = cache
	}
}

// WithGrpcDialOptionsLCOption sets the gRPC dial options for client connection setup.
// Useful for adding client interceptors. These options are ignored if WithGrpcConnection is used.
func WithGrpcDialOptionsLCOption(opts ...grpc.DialOption) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.grpcOptions = opts
	}
}

// WithGrpcConnectionLCOption sets the gRPC client connection directly.
// Useful for running the client in the same process as the authorization service.
func WithGrpcConnectionLCOption(conn grpc.ClientConnInterface) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.grpcConn = conn
	}
}

func WithTracerLCOption(tracer trace.Tracer) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.tracer = tracer
	}
}

// WithDisableAccessTokenLCOption is an option to disable access token authorization.
// Warning: Using this option means there won't be any service authorization.
func WithDisableAccessTokenLCOption() LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.authCfg.accessTokenAuthEnabled = false
	}
}

// -----
// Initialization
// -----

func NewLegacyClient(cfg *ClientConfig, opts ...LegacyClientOption) (*LegacyClientImpl, error) {
	if cfg == nil {
		return nil, ErrMissingConfig
	}
	cfg.accessTokenAuthEnabled = true

	client := &LegacyClientImpl{authCfg: cfg}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Instantiate the cache
	if client.cache == nil {
		client.cache = cache.NewLocalCache(cache.Config{
			Expiry:          cache.DefaultExpiration,
			CleanupInterval: 1 * cache.DefaultExpiration,
		})
	}

	if client.tracer == nil {
		client.tracer = noop.Tracer{}
	}

	// Instantiate the client
	if client.grpcConn == nil {
		if cfg.RemoteAddress == "" {
			return nil, fmt.Errorf("missing remote address: %w", ErrMissingConfig)
		}

		tp := tracerProvider{tracer: client.tracer}
		grpcOpts := client.grpcOptions
		grpcOpts = append(grpcOpts, grpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(&tp))))

		conn, err := grpc.NewClient(cfg.RemoteAddress, grpcOpts...)
		if err != nil {
			return nil, err
		}
		client.grpcConn = conn
	}
	client.clientV1 = authzv1.NewAuthzServiceClient(client.grpcConn)

	return client, nil
}

// -----
// Implementation
// -----

func (r *CheckRequest) Validate() error {
	if r.Namespace == "" {
		return ErrMissingRequestNamespace
	}

	if _, err := claims.ParseNamespace(r.Namespace); err != nil {
		return ErrInvalidRequestNamespace
	}

	if r.Action == "" {
		return ErrMissingRequestAction
	}

	if r.Name != "" {
		if r.Attribute == "" {
			return ErrMissingRequestAttribute
		}
		if r.Resource == "" {
			return ErrMissingRequestResource
		}
	}

	return nil
}

func (c *LegacyClientImpl) Check(ctx context.Context, caller claims.AuthInfo, req *CheckRequest) (CheckResponse, error) {
	ctx, span := c.tracer.Start(ctx, "LegacyClientImpl.Check")
	defer span.End()

	if err := req.Validate(); err != nil {
		span.RecordError(err)
		return checkResponseDenied, err
	}

	if err := c.validateCaller(caller); err != nil {
		span.RecordError(err)
		return checkResponseDenied, err
	}

	if !c.validateCallerNamespace(caller, req.Namespace) {
		return checkResponseDenied, nil
	}

	accessClaims := caller.GetAccess()
	identityClaims := caller.GetIdentity()

	if c.authCfg.accessTokenAuthEnabled && accessClaims != nil && !accessClaims.IsNil() {
		span.SetAttributes(attribute.String("service", accessClaims.Subject()))
	}
	span.SetAttributes(attribute.String("namespace", req.Namespace))
	span.SetAttributes(attribute.String("action", req.Action))
	if req.Name != "" {
		span.SetAttributes(attribute.String("object", fmt.Sprintf("%s:%s:%s", req.Resource, req.Attribute, req.Name)))
	}
	if req.Parent != "" {
		span.SetAttributes(attribute.String("parent", req.Parent))
	}
	span.SetAttributes(attribute.Bool("with_user", identityClaims != nil && !identityClaims.IsNil()))

	// No user => check on the service permissions
	if identityClaims == nil || identityClaims.IsNil() {
		// access token check is disabled => we can skip the authz service
		if !c.authCfg.accessTokenAuthEnabled {
			return checkResponseAllowed, nil
		}

		if accessClaims == nil || accessClaims.IsNil() {
			return checkResponseDenied, ErrMissingCaller
		}

		perms := accessClaims.Permissions()
		for _, p := range perms {
			if p == req.Action {
				return checkResponseAllowed, nil
			}
		}
		return checkResponseDenied, nil
	}

	span.SetAttributes(attribute.String("subject", identityClaims.Subject()))

	// Only check the service permissions if the access token check is enabled
	if c.authCfg.accessTokenAuthEnabled {
		if accessClaims == nil || accessClaims.IsNil() {
			return checkResponseDenied, ErrMissingCaller
		}

		// Make sure the service is allowed to perform the requested action
		serviceIsAllowedAction := false
		for _, p := range accessClaims.DelegatedPermissions() {
			if p == req.Action {
				serviceIsAllowedAction = true
				break
			}
		}
		if !serviceIsAllowedAction {
			return checkResponseDenied, nil
		}
	}

	res, err := c.check(ctx, caller, req)
	if err != nil {
		span.RecordError(err)
		return checkResponseDenied, err
	}

	// Check if the user has access to any of the requested resources
	return CheckResponse{Allowed: res}, nil
}

func (c *LegacyClientImpl) validateCaller(caller claims.AuthInfo) error {
	accessClaims := caller.GetAccess()
	if c.authCfg.accessTokenAuthEnabled && (accessClaims == nil || accessClaims.IsNil()) {
		return ErrMissingCaller
	}
	idClaims := caller.GetIdentity()
	if idClaims != nil && !idClaims.IsNil() && idClaims.Subject() == "" {
		return ErrMissingSubject
	}
	return nil
}

func (c *LegacyClientImpl) validateCallerNamespace(caller claims.AuthInfo, expectedNamespace string) bool {
	// Check both AccessToken and IDToken (if present) for namespace match
	accessClaims := caller.GetAccess()
	accessTokenMatch := !c.authCfg.accessTokenAuthEnabled ||
		(accessClaims != nil && !accessClaims.IsNil() && claims.NamespaceMatches(accessClaims, expectedNamespace))

	idClaims := caller.GetIdentity()
	idTokenMatch := idClaims == nil || idClaims.IsNil() || claims.NamespaceMatches(idClaims, expectedNamespace)

	return accessTokenMatch && idTokenMatch
}

func (c *LegacyClientImpl) check(ctx context.Context, caller claims.AuthInfo, req *CheckRequest) (bool, error) {
	ctx, span := c.tracer.Start(ctx, "LegacyClientImpl.check")
	defer span.End()

	scope := ""
	parentScope := ""
	if req.Name != "" {
		scope = fmt.Sprintf("%s:%s:%s", req.Resource, req.Attribute, req.Name)
	}
	if req.Parent != "" {
		parentScope = fmt.Sprintf("%s:%s:%s", "folders", "uid", req.Parent)
	}

	// Check the cache
	key := checkCacheKey(req.Namespace, caller.GetIdentity().Subject(), req.Action, scope, parentScope)
	ctrl, err := c.getCachedCheck(ctx, key)
	if err == nil || !errors.Is(err, cache.ErrNotFound) {
		return ctrl, err
	}

	checkReq := &authzv1.CheckRequest{
		Namespace: req.Namespace,
		Subject:   caller.GetIdentity().Subject(),
		Action:    req.Action,
		Scope:     scope,
		Parent:    parentScope,
	}

	// Instantiate a new context for the request
	outCtx := newOutgoingContext(ctx)

	// Query the authz service
	resp, err := c.clientV1.Check(outCtx, checkReq)
	if err != nil {
		return false, err
	}

	// Cache the result
	err = c.cacheCheck(ctx, key, resp.Allowed)

	return resp.Allowed, err
}

// newOutgoingContext creates a new context that will be canceled when the input context is canceled.
func newOutgoingContext(ctx context.Context) context.Context {
	outCtx, cancel := context.WithCancel(context.Background())

	// Propagate the span into the new context
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		outCtx = trace.ContextWithSpanContext(outCtx, spanContext)
	}

	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-outCtx.Done():
			// exit
		}
	}()

	return outCtx
}

// -----
// CACHE
// -----

func checkCacheKey(namespace, subject, action, object, parent string) string {
	return fmt.Sprintf("read-%s-%s-%s-%s-%s", namespace, subject, action, object, parent)
}

func (c *LegacyClientImpl) cacheCheck(ctx context.Context, key string, allowed bool) error {
	ctx, span := c.tracer.Start(ctx, "LegacyClientImpl.cacheCheck")
	defer span.End()

	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(allowed)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}

func (c *LegacyClientImpl) getCachedCheck(ctx context.Context, key string) (bool, error) {
	ctx, span := c.tracer.Start(ctx, "LegacyClientImpl.getCachedCheck")
	defer span.End()

	data, err := c.cache.Get(ctx, key)
	if err != nil {
		return false, err
	}

	var allowed bool
	err = gob.NewDecoder(bytes.NewReader(data)).Decode(&allowed)
	if err != nil {
		return false, err
	}
	return allowed, nil
}
