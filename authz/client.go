package authz

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"strings"
	"time"

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
	ErrMissingRequestGroup     = errors.New("missing request group")
	ErrMissingRequestResource  = errors.New("missing request resource")
	ErrMissingRequestVerb      = errors.New("missing request verb")
	ErrMissingCaller           = errors.New("missing caller")
	ErrMissingSubject          = errors.New("missing subject")

	checkResponseDenied  = CheckResponse{Allowed: false}
	checkResponseAllowed = CheckResponse{Allowed: true}
)

// CheckRequest describes the requested access.
// This is designed bo to play nicely with the kubernetes authorization system:
// https://github.com/kubernetes/kubernetes/blob/v1.30.3/staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go#L28
type CheckRequest struct {
	// The requested access verb.
	// this includes get, list, watch, create, update, patch, delete, deletecollection, and proxy,
	// or the lowercased HTTP verb associated with non-API requests (this includes get, put, post, patch, and delete)
	Verb string

	// API group (dashboards.grafana.app)
	Group string

	// ~Kind eg dashboards
	Resource string

	// tenant isolation
	Namespace string

	// The specific resource
	// In grafana, this was historically called "UID", but in k8s, it is the name
	Name string

	// Optional subresource
	Subresource string

	// For non-resource requests, this will be the requested URL path
	Path string

	// Folder is the parent folder of the requested resource
	Folder string
}

type CheckResponse struct {
	// Allowed is true if the request is allowed, false otherwise.
	Allowed bool
}

type AccessChecker interface {
	// Check checks whether the user can perform the given action for all requests
	Check(ctx context.Context, id claims.AuthInfo, req CheckRequest) (CheckResponse, error)
}

type ListRequest struct {
	// API group (dashboards.grafana.app)
	Group string

	// ~Kind eg dashboards
	Resource string

	// tenant isolation
	Namespace string

	// Optional subresource
	Subresource string
}

// TODO: Should the namespace be specified in the request instead.
// I don't think we'll be able to Compile over multiple namespaces.
// Checks access while iterating within a resource
type ItemChecker func(namespace string, name, folder string) bool

type AccessLister interface {
	// Compile generates a function to check whether the id has access to items matching a request
	// This is particularly useful when you want to verify access to a list of resources.
	// Returns nil if there is no access to any matching items
	Compile(ctx context.Context, id claims.AuthInfo, req ListRequest) (ItemChecker, error)
}

type AccessClient interface {
	AccessChecker
	AccessLister
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
var _ AccessChecker = (*ClientImpl)(nil)

type AuthzClientOption func(*ClientImpl)

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

func WithCacheClientOption(cache cache.Cache) AuthzClientOption {
	return func(c *ClientImpl) {
		c.cache = cache
	}
}

// WithGrpcDialOptionsClientOption sets the gRPC dial options for client connection setup.
// Useful for adding client interceptors. These options are ignored if WithGrpcConnection is used.
func WithGrpcDialOptionsClientOption(opts ...grpc.DialOption) AuthzClientOption {
	return func(c *ClientImpl) {
		c.grpcOptions = opts
	}
}

// WithGrpcConnectionClientOption sets the gRPC client connection directly.
// Useful for running the client in the same process as the authorization service.
func WithGrpcConnectionClientOption(conn grpc.ClientConnInterface) AuthzClientOption {
	return func(c *ClientImpl) {
		c.grpcConn = conn
	}
}

func WithTracerClientOption(tracer trace.Tracer) AuthzClientOption {
	return func(c *ClientImpl) {
		c.tracer = tracer
	}
}

// WithDisableAccessTokenClientOption is an option to disable access token authorization.
// Warning: Using this option means there won't be any service authorization.
func WithDisableAccessTokenClientOption() AuthzClientOption {
	return func(c *ClientImpl) {
		c.authCfg.accessTokenAuthEnabled = false
	}
}

// -----
// Initialization
// -----

func NewClient(cfg *ClientConfig, opts ...AuthzClientOption) (*ClientImpl, error) {
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
			Expiry:          5 * time.Minute,
			CleanupInterval: 10 * time.Minute,
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

func validateAccessRequest(req CheckRequest) error {
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

func (c *ClientImpl) check(ctx context.Context, id claims.AuthInfo, req *CheckRequest) (bool, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.hasAccess")
	defer span.End()

	key := checkCacheKey(id.GetSubject(), req)
	res, err := c.getCachedCheck(ctx, key)
	if err == nil {
		return res, nil
	}

	checkReq := &authzv1.CheckRequest{
		Subject:     id.GetSubject(),
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

// wildcardMatch efficiently checks if an input string matches a given pattern.
// e.g. wildcardMatch("*foo*bar*", "foobar") => true
func wildcardMatch(pattern, input string) bool {
	// empty pattern only matches empty input
	if len(pattern) == 0 {
		return len(input) == 0
	}

	patternParts := strings.Split(pattern, "*")

	// leading pattern part must match
	if len(patternParts[0]) > 0 && !strings.HasPrefix(input, patternParts[0]) {
		return false
	}

	inputIndex := 0
	// iterate over the pattern parts
	for i := range patternParts {
		// leading/trailing '*' or consecutive '*'
		if patternParts[i] == "" {
			continue
		}

		nextIndex := strings.Index(input[inputIndex:], patternParts[i])
		if nextIndex == -1 {
			return false
		}
		inputIndex += nextIndex + len(patternParts[i])
	}

	// trailing '*' matches input leftovers
	if pattern[len(pattern)-1] == '*' {
		return true
	}

	return inputIndex == len(input)
}

func hasPermissionInToken(tokenPermissions []string, group, resource, verb, name string) bool {
	for _, p := range tokenPermissions {
		parts := strings.Split(p, ":")
		if len(parts) != 2 {
			continue
		}
		pVerb := parts[1]
		if pVerb != "*" && pVerb != verb {
			continue
		}

		parts = strings.Split(parts[0], "/")
		if len(parts) < 2 {
			continue
		}

		pGroup := parts[0]
		pResource := parts[1]
		if !wildcardMatch(pGroup, group) || !wildcardMatch(pResource, resource) {
			continue
		}
		if len(parts) == 2 {
			return true
		}

		pName := parts[2]
		if !wildcardMatch(pName, name) {
			continue
		}
		return true
	}
	return false
}

func (c *ClientImpl) Check(ctx context.Context, id claims.AuthInfo, req CheckRequest) (CheckResponse, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.Check")
	defer span.End()

	if err := validateAccessRequest(req); err != nil {
		span.RecordError(err)
		return checkResponseDenied, err
	}

	if err := c.validateCaller(id); err != nil {
		span.RecordError(err)
		return checkResponseDenied, err
	}

	if !c.validateCallerNamespace(id, req.Namespace) {
		return checkResponseDenied, nil
	}

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

	isService := claims.IsIdentityType(id.GetIdentityType(), claims.TypeAccessPolicy)
	span.SetAttributes(attribute.Bool("with_user", !isService))

	// No user => check on the service permissions
	if isService {
		// access token check is disabled => we can skip the authz service
		if !c.authCfg.accessTokenAuthEnabled {
			return checkResponseAllowed, nil
		}

		serviceIsAllowedAction := hasPermissionInToken(id.GetTokenPermissions(), req.Group, req.Resource, req.Verb, req.Name)
		return CheckResponse{Allowed: serviceIsAllowedAction}, nil
	}

	span.SetAttributes(attribute.String("subject", id.GetSubject()))

	// Only check the service permissions if the access token check is enabled
	if c.authCfg.accessTokenAuthEnabled {
		serviceIsAllowedAction := hasPermissionInToken(id.GetTokenDelegatedPermissions(), req.Group, req.Resource, req.Verb, req.Name)
		if !serviceIsAllowedAction {
			return checkResponseDenied, nil
		}
	}

	res, err := c.check(ctx, id, &req)
	if err != nil {
		span.RecordError(err)
		return checkResponseDenied, err
	}

	// Check if the user has access to any of the requested resources
	return CheckResponse{Allowed: res}, nil
}

func (c *ClientImpl) validateCaller(caller claims.AuthInfo) error {
	if !c.authCfg.accessTokenAuthEnabled && claims.IsIdentityType(caller.GetIdentityType(), claims.TypeAccessPolicy) {
		return nil
	}

	if caller.GetSubject() == "" {
		return ErrMissingCaller
	}
	return nil
}

func (c *ClientImpl) validateCallerNamespace(caller claims.AuthInfo, expectedNamespace string) bool {
	if !c.authCfg.accessTokenAuthEnabled && claims.IsIdentityType(caller.GetIdentityType(), claims.TypeAccessPolicy) {
		return true
	}

	return claims.NamespaceMatches(caller.GetNamespace(), expectedNamespace)
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

func checkCacheKey(subj string, req *CheckRequest) string {
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
