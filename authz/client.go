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
	"github.com/grafana/authlib/types"
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

	checkResponseDenied  = types.CheckResponse{Allowed: false}
	checkResponseAllowed = types.CheckResponse{Allowed: true}
)

type ClientConfig struct {
	// RemoteAddress is the address of the authz service. It should be in the format "host:port".
	RemoteAddress string

	// accessTokenAuthEnabled is a flag to enable access token authentication.
	// If disabled, no service authentication will be performed. Defaults to true.
	accessTokenAuthEnabled bool
}

// ClientImpl will implement the types.AccessClient interface
// Once we are able to deal with folder permissions expansion.
var _ types.AccessClient = (*ClientImpl)(nil)

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

func (c *ClientImpl) check(ctx context.Context, id types.AuthInfo, req *types.CheckRequest) (bool, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.hasAccess")
	defer span.End()

	idIsServiceAccount := types.IsIdentityType(id.GetIdentityType(), types.TypeServiceAccount)
	if !idIsServiceAccount && (req.Name == "k6-app" || req.Folder == "k6-app") {
		return false, nil
	}

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

func hasPermissionInToken(tokenPermissions []string, group, resource, verb string) bool {
	for _, p := range tokenPermissions {
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			continue
		}
		pVerb := parts[1]
		if pVerb != "*" && pVerb != verb {
			continue
		}

		parts = strings.SplitN(parts[0], "/", 3)
		switch len(parts) {
		case 1:
			if parts[0] == group {
				return true
			}
		case 2:
			if parts[0] == group && parts[1] == resource {
				return true
			}
		}
	}
	return false
}

func (c *ClientImpl) Check(ctx context.Context, id types.AuthInfo, req types.CheckRequest) (types.CheckResponse, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.Check")
	defer span.End()

	if err := validateCheckRequest(req); err != nil {
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

	isService := types.IsIdentityType(id.GetIdentityType(), types.TypeAccessPolicy)
	span.SetAttributes(attribute.Bool("with_user", !isService))

	// No user => check on the service permissions
	if isService {
		// access token check is disabled => we can skip the authz service
		if !c.authCfg.accessTokenAuthEnabled {
			return checkResponseAllowed, nil
		}

		permissions := id.GetTokenPermissions()
		serviceIsAllowedAction := hasPermissionInToken(permissions, req.Group, req.Resource, req.Verb)

		span.SetAttributes(attribute.Int("permissions", len(permissions)))
		span.SetAttributes(attribute.Bool("service_allowed", serviceIsAllowedAction))

		return types.CheckResponse{Allowed: serviceIsAllowedAction}, nil
	}

	span.SetAttributes(attribute.String("subject", id.GetSubject()))

	// Only check the service permissions if the access token check is enabled
	if c.authCfg.accessTokenAuthEnabled {
		permissions := id.GetTokenDelegatedPermissions()
		serviceIsAllowedAction := hasPermissionInToken(permissions, req.Group, req.Resource, req.Verb)

		span.SetAttributes(attribute.Int("delegated_permissions", len(permissions)))
		span.SetAttributes(attribute.Bool("service_allowed", serviceIsAllowedAction))

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
	span.SetAttributes(attribute.Bool("user_allowed", res))
	return types.CheckResponse{Allowed: res}, nil
}

func (c *ClientImpl) compile(ctx context.Context, id types.AuthInfo, list *types.ListRequest) (*itemChecker, error) {
	key := itemCheckerCacheKey(id.GetSubject(), list)
	checker, err := c.getCachedItemChecker(ctx, key)
	if err == nil {
		return checker, nil
	}

	// Instantiate a new context for the request
	outCtx := newOutgoingContext(ctx)

	// Query the authz service
	listReq := &authzv1.ListRequest{
		Subject:     id.GetSubject(),
		Group:       list.Group,
		Resource:    list.Resource,
		Verb:        list.Verb,
		Namespace:   list.Namespace,
		Subresource: list.Subresource,
	}

	resp, err := c.clientV1.List(outCtx, listReq)
	if err != nil {
		return nil, err
	}

	checker = newItemChecker(resp)
	err = c.cacheItemChecker(ctx, key, checker)

	return checker, err
}

func (c *ClientImpl) Compile(ctx context.Context, id types.AuthInfo, list types.ListRequest) (types.ItemChecker, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.List")
	defer span.End()

	if err := validateListRequest(list); err != nil {
		span.RecordError(err)
		return nil, err
	}

	if err := c.validateCaller(id); err != nil {
		span.RecordError(err)
		return nil, err
	}

	if !c.validateCallerNamespace(id, list.Namespace) {
		return denyAllChecker, nil
	}

	span.SetAttributes(attribute.String("namespace", list.Namespace))
	span.SetAttributes(attribute.String("group", list.Group))
	span.SetAttributes(attribute.String("resource", list.Resource))
	span.SetAttributes(attribute.String("verb", list.Verb))

	isService := types.IsIdentityType(id.GetIdentityType(), types.TypeAccessPolicy)
	span.SetAttributes(attribute.Bool("with_user", !isService))

	// No user => check on the service permissions
	if isService {
		// access token check is disabled => we can skip the authz service
		if !c.authCfg.accessTokenAuthEnabled {
			return allowAllChecker(list.Namespace, true), nil
		}

		if hasPermissionInToken(id.GetTokenPermissions(), list.Group, list.Resource, list.Verb) {
			return allowAllChecker(list.Namespace, true), nil
		}
		return denyAllChecker, nil
	}

	// Only check the service permissions if the access token check is enabled
	if c.authCfg.accessTokenAuthEnabled {
		if !hasPermissionInToken(id.GetTokenDelegatedPermissions(), list.Group, list.Resource, list.Verb) {
			return denyAllChecker, nil
		}
	}

	checker, err := c.compile(ctx, id, &list)
	if err != nil {
		span.RecordError(err)
		return denyAllChecker, err
	}

	return checker.fn(list.Namespace, id), nil
}

// Validate input

func validateCheckRequest(req types.CheckRequest) error {
	if req.Namespace == "" {
		return ErrMissingRequestNamespace
	}

	if _, err := types.ParseNamespace(req.Namespace); err != nil {
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

func validateListRequest(req types.ListRequest) error {
	if req.Namespace == "" {
		return ErrMissingRequestNamespace
	}

	if _, err := types.ParseNamespace(req.Namespace); err != nil {
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

func (c *ClientImpl) validateCaller(caller types.AuthInfo) error {
	if !c.authCfg.accessTokenAuthEnabled && types.IsIdentityType(caller.GetIdentityType(), types.TypeAccessPolicy) {
		return nil
	}

	if caller.GetSubject() == "" {
		return ErrMissingCaller
	}
	return nil
}

func (c *ClientImpl) validateCallerNamespace(caller types.AuthInfo, expectedNamespace string) bool {
	if !c.authCfg.accessTokenAuthEnabled && types.IsIdentityType(caller.GetIdentityType(), types.TypeAccessPolicy) {
		return true
	}

	return types.NamespaceMatches(caller.GetNamespace(), expectedNamespace)
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

func checkCacheKey(subj string, req *types.CheckRequest) string {
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

func itemCheckerCacheKey(subj string, req *types.ListRequest) string {
	return fmt.Sprintf("list-%s-%s-%s-%s-%s-%s", req.Namespace, subj, req.Group, req.Resource, req.Verb, req.Subresource)
}

func (c *ClientImpl) cacheItemChecker(ctx context.Context, key string, checker *itemChecker) error {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.cacheList")
	defer span.End()

	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(checker)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}

func (c *ClientImpl) getCachedItemChecker(ctx context.Context, key string) (*itemChecker, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.getCachedList")
	defer span.End()

	data, err := c.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	resp := &itemChecker{}
	err = gob.NewDecoder(bytes.NewReader(data)).Decode(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// -----
// ItemChecker
// -----

var denyAllChecker = func(namespace string, name, folder string) bool { return false }

func allowAllChecker(expectedNamespace string, isServiceAccount bool) types.ItemChecker {
	return func(namespace string, name, folder string) bool {
		if !isServiceAccount && (name == "k6-app" || folder == "k6-app") {
			return false
		}
		return types.NamespaceMatches(namespace, expectedNamespace)
	}
}

type itemChecker struct {
	All     bool
	Items   map[string]bool
	Folders map[string]bool
}

func newItemChecker(resp *authzv1.ListResponse) *itemChecker {
	if resp == nil {
		return &itemChecker{}
	}

	if resp.All {
		return &itemChecker{All: true}
	}

	res := &itemChecker{
		Items:   make(map[string]bool, len(resp.Items)),
		Folders: make(map[string]bool, len(resp.Folders)),
	}
	for _, i := range resp.Items {
		res.Items[i] = true
	}
	for _, f := range resp.Folders {
		res.Folders[f] = true
	}
	return res
}

// fn generates a ItemChecker function that can check user access to items.
func (c *itemChecker) fn(expectedNamespace string, id types.AuthInfo) types.ItemChecker {
	idIsSvcAccount := types.IsIdentityType(id.GetIdentityType(), types.TypeServiceAccount)
	if c.All {
		return allowAllChecker(expectedNamespace, idIsSvcAccount)
	}

	if len(c.Items) == 0 && len(c.Folders) == 0 {
		return denyAllChecker
	}

	return func(namespace string, name, folder string) bool {
		if !types.NamespaceMatches(namespace, expectedNamespace) {
			return false
		}
		if !idIsSvcAccount && (name == "k6-app" || folder == "k6-app") {
			return false
		}
		return c.Items[name] || c.Folders[folder]
	}
}
