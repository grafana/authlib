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
	ErrMissingRequestVerb      = errors.New("missing request verb")
	ErrMissingRequestGroup     = errors.New("missing request group")
	ErrMissingCaller           = errors.New("missing caller")
	ErrMissingSubject          = errors.New("missing subject")

	checkAllowed = claims.CheckResponse{Allowed: true}
	checkDenied  = claims.CheckResponse{Allowed: false}
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
type ClientConfig struct {
	// RemoteAddress is the address of the authz service. It should be in the format "host:port".
	RemoteAddress string

	// accessTokenAuthEnabled is a flag to enable access token authentication.
	// If disabled, no service authentication will be performed. Defaults to true.
	accessTokenAuthEnabled bool
}

// ClientImpl will implement the claims.AccessClient interface
// Once we are able to deal with folder permissions expansion.
var _ claims.AccessChecker = (*ClientImpl)(nil)

type LegacyClientOption func(*ClientImpl)

type ClientImpl struct {
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

func WithCacheClientOption(cache cache.Cache) LegacyClientOption {
	return func(c *ClientImpl) {
		c.cache = cache
	}
}

// WithGrpcDialOptionsClientOption sets the gRPC dial options for client connection setup.
// Useful for adding client interceptors. These options are ignored if WithGrpcConnection is used.
func WithGrpcDialOptionsClientOption(opts ...grpc.DialOption) LegacyClientOption {
	return func(c *ClientImpl) {
		c.grpcOptions = opts
	}
}

// WithGrpcConnectionClientOption sets the gRPC client connection directly.
// Useful for running the client in the same process as the authorization service.
func WithGrpcConnectionClientOption(conn grpc.ClientConnInterface) LegacyClientOption {
	return func(c *ClientImpl) {
		c.grpcConn = conn
	}
}

func WithTracerClientOption(tracer trace.Tracer) LegacyClientOption {
	return func(c *ClientImpl) {
		c.tracer = tracer
	}
}

// WithDisableAccessTokenClientOption is an option to disable access token authorization.
// Warning: Using this option means there won't be any service authorization.
func WithDisableAccessTokenClientOption() LegacyClientOption {
	return func(c *ClientImpl) {
		c.authCfg.accessTokenAuthEnabled = false
	}
}

// -----
// Initialization
// -----

func NewClient(cfg *ClientConfig, opts ...LegacyClientOption) (*ClientImpl, error) {
	if cfg == nil {
		return nil, ErrMissingConfig
	}
	cfg.accessTokenAuthEnabled = true

	client := &ClientImpl{authCfg: cfg}

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

func validateAccessRequest(req claims.CheckRequest) error {
	if req.Namespace == "" {
		return ErrMissingRequestNamespace
	}

	if _, err := claims.ParseNamespace(req.Namespace); err != nil {
		return ErrInvalidRequestNamespace
	}

	if req.Resource == "" {
		return ErrMissingRequestResource
	}
	if req.Group == "" {
		return ErrMissingRequestGroup
	}
	if req.Verb == "" {
		return ErrMissingRequestVerb
	}

	return nil
}

func (c *ClientImpl) check(ctx context.Context, id claims.AuthInfo, req *claims.CheckRequest) (bool, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.hasAccess")
	defer span.End()

	key := checkCacheKey(id.GetIdentity().Subject(), req)
	res, err := c.getCachedCheck(ctx, key)
	if err == nil {
		return res, nil
	}

	checkReq := &authzv1.CheckRequest{
		Subject:     id.GetIdentity().Subject(),
		Verb:        req.Verb,
		Group:       req.Group,
		Resource:    req.Resource,
		Namespace:   req.Namespace,
		Name:        req.Name,
		Subresource: req.Subresource,
		Path:        req.Path,
		Folder:      req.Folder,
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

// HasAccess implements claims.AccessClient.
func (c *ClientImpl) Check(ctx context.Context, id claims.AuthInfo, req claims.CheckRequest) (claims.CheckResponse, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.Check")
	defer span.End()

	if err := validateAccessRequest(req); err != nil {
		span.RecordError(err)
		return checkDenied, err
	}

	if err := c.validateCaller(id); err != nil {
		span.RecordError(err)
		return checkDenied, err
	}

	if !c.validateCallerNamespace(id, req.Namespace) {
		return checkDenied, nil
	}

	accessClaims := id.GetAccess()
	identityClaims := id.GetIdentity()

	span.SetAttributes(attribute.String("namespace", req.Namespace))
	span.SetAttributes(attribute.String("verb", req.Verb))
	span.SetAttributes(attribute.String("group", req.Group))
	span.SetAttributes(attribute.String("resource", req.Resource))
	if req.Name != "" {
		span.SetAttributes(attribute.String("name", req.Name))
	}
	if req.Path != "" {
		span.SetAttributes(attribute.String("path", req.Path))
	}
	span.SetAttributes(attribute.Bool("with_user", identityClaims != nil && !identityClaims.IsNil()))

	// No user => check on the service permissions
	if identityClaims == nil || identityClaims.IsNil() {
		// access token check is disabled => we can skip the authz service
		if !c.authCfg.accessTokenAuthEnabled {
			return checkAllowed, nil
		}

		if accessClaims == nil || accessClaims.IsNil() {
			return checkDenied, ErrMissingCaller
		}

		action := fmt.Sprintf("%s/%s:%s", req.Group, req.Resource, req.Verb)
		perms := accessClaims.Permissions()
		for _, p := range perms {
			if p == action {
				return checkAllowed, nil
			}
		}
		return checkDenied, nil
	}

	span.SetAttributes(attribute.String("subject", identityClaims.Subject()))

	// Only check the service permissions if the access token check is enabled
	if c.authCfg.accessTokenAuthEnabled {
		if accessClaims == nil || accessClaims.IsNil() {
			return checkDenied, ErrMissingCaller
		}

		// Make sure the service is allowed to perform the requested action
		action := fmt.Sprintf("%s/%s:%s", req.Group, req.Resource, req.Verb)
		serviceIsAllowedAction := false
		for _, p := range accessClaims.DelegatedPermissions() {
			if p == action {
				serviceIsAllowedAction = true
				break
			}
		}
		if !serviceIsAllowedAction {
			return checkDenied, nil
		}
	}

	res, err := c.check(ctx, id, &req)
	if err != nil {
		span.RecordError(err)
		return checkDenied, err
	}

	// Check if the user has access to any of the requested resources
	return claims.CheckResponse{Allowed: res}, nil
}

func (c *ClientImpl) validateCaller(caller claims.AuthInfo) error {
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

func (c *ClientImpl) validateCallerNamespace(caller claims.AuthInfo, expectedNamespace string) bool {
	// Check both AccessToken and IDToken (if present) for namespace match
	accessClaims := caller.GetAccess()
	accessTokenMatch := !c.authCfg.accessTokenAuthEnabled ||
		(accessClaims != nil && !accessClaims.IsNil() && claims.NamespaceMatches(accessClaims, expectedNamespace))

	idClaims := caller.GetIdentity()
	idTokenMatch := idClaims == nil || idClaims.IsNil() || claims.NamespaceMatches(idClaims, expectedNamespace)

	return accessTokenMatch && idTokenMatch
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

func checkCacheKey(subj string, req *claims.CheckRequest) string {
	return fmt.Sprintf("check-%s-%s-%s-%s-%s-%s-%s-%s-%s", req.Namespace, subj, req.Group, req.Resource, req.Verb, req.Name, req.Subresource, req.Path, req.Folder)
}

func (c *ClientImpl) cacheCheck(ctx context.Context, key string, allowed bool) error {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.cacheCheck")
	defer span.End()

	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(allowed)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}

func (c *ClientImpl) getCachedCheck(ctx context.Context, key string) (bool, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.getCachedCheck")
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
