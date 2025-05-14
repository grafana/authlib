package authz

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/types"
)

var (
	checkResponseDenied = types.CheckResponse{Allowed: false}

	k6FolderUID = "k6-app"
)

var (
	ErrMissingAuthInfo    = errors.New("missing auth info")
	ErrNamespaceMissmatch = errors.New("namespace missmatch")
)

func IsUnauthorizedErr(err error) bool {
	return errors.Is(err, ErrNamespaceMissmatch)
}

// ClientImpl will implement the types.AccessClient interface
// Once we are able to deal with folder permissions expansion.
var _ types.AccessClient = (*ClientImpl)(nil)

type AuthzClientOption func(*ClientImpl)

type ClientImpl struct {
	clientV1 authzv1.AuthzServiceClient
	cache    cache.Cache
	tracer   trace.Tracer
}

func (c *ClientImpl) BatchCheck(ctx context.Context, info types.AuthInfo, req types.BatchCheckRequest) (types.BatchCheckResponse, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.BatchCheck")
	defer span.End()

	if err := validateAuthInfo(info, req.Namespace, span); err != nil {
		return BatchCheckResponseDenied(req), err
	}

	span.SetAttributes(attribute.String("subject", info.GetSubject()))
	span.SetAttributes(attribute.String("namespace", req.Namespace))

	isService := types.IsIdentityType(info.GetIdentityType(), types.TypeAccessPolicy)
	span.SetAttributes(attribute.Bool("with_user", !isService))

	batchRes := types.BatchCheckResponse{
		Groups: make(map[string]types.BatchCheckGroupResponse),
	}

	for _, item := range req.Items {
		// TODO refactor to make this call Check to avoid code duplication

		// TODO record BatchCheckItem info in the span?
		groupResource := types.FormatGroupResource(item.Group, item.Resource, item.Subresource)
		if _, ok := batchRes.Groups[groupResource]; !ok {
			batchRes.Groups[groupResource] = types.BatchCheckGroupResponse{
				Items: make(map[string]types.BatchCheckItemResponse),
			}
		}

		if err := types.ValidateBatchCheckItem(item); err != nil {
			batchRes.Groups[groupResource].Items[item.Name] = types.BatchCheckItemResponse{Allowed: false}
			continue
		}

		// No user => check on the service permissions
		if isService {
			permissions := info.GetTokenPermissions()
			serviceIsAllowedAction := hasPermissionInToken(permissions, item.Group, item.Resource, item.Verb)

			//span.SetAttributes(attribute.Int("permissions", len(permissions)))
			//span.SetAttributes(attribute.Bool("service_allowed", serviceIsAllowedAction))

			batchRes.Groups[groupResource].Items[item.Name] = types.BatchCheckItemResponse{Allowed: serviceIsAllowedAction}
			continue
		}

		// Only check the service permissions if the access token check is enabled
		permissions := info.GetTokenDelegatedPermissions()
		serviceIsAllowedAction := hasPermissionInToken(permissions, item.Group, item.Resource, item.Verb)

		//span.SetAttributes(attribute.Int("delegated_permissions", len(permissions)))
		//span.SetAttributes(attribute.Bool("service_allowed", serviceIsAllowedAction))

		if !serviceIsAllowedAction {
			batchRes.Groups[groupResource].Items[item.Name] = types.BatchCheckItemResponse{Allowed: false}
			continue
		}

		check, err := c.check(ctx, info, BatchItemToCheckRequest(req.Namespace, &item))
		if err != nil {
			batchRes.Groups[groupResource].Items[item.Name] = types.BatchCheckItemResponse{Allowed: false}
			continue
		}
		batchRes.Groups[groupResource].Items[item.Name] = types.BatchCheckItemResponse{Allowed: check}
	}
	return batchRes, nil
}

func BatchItemToCheckRequest(namespace string, item *types.BatchCheckItem) *types.CheckRequest {
	return &types.CheckRequest{
		Namespace:   namespace,
		Group:       item.Group,
		Resource:    item.Resource,
		Verb:        item.Verb,
		Name:        item.Name,
		Subresource: item.Subresource,
		Folder:      item.Folder,
	}
}

func BatchCheckResponseDenied(req types.BatchCheckRequest) types.BatchCheckResponse {
	batchRes := types.BatchCheckResponse{
		Groups: make(map[string]types.BatchCheckGroupResponse),
	}

	for _, item := range req.Items {
		groupResource := types.FormatGroupResource(item.Group, item.Resource, item.Subresource)
		if _, ok := batchRes.Groups[groupResource]; !ok {
			batchRes.Groups[groupResource] = types.BatchCheckGroupResponse{
				Items: make(map[string]types.BatchCheckItemResponse),
			}
		}
		batchRes.Groups[groupResource].Items[item.Name] = types.BatchCheckItemResponse{Allowed: false}
	}

	return batchRes
}

// -----
// Options
// -----

func WithCacheClientOption(cache cache.Cache) AuthzClientOption {
	return func(c *ClientImpl) {
		c.cache = cache
	}
}

func WithTracerClientOption(tracer trace.Tracer) AuthzClientOption {
	return func(c *ClientImpl) {
		c.tracer = tracer
	}
}

// -----
// Initialization
// -----

func NewClient(cc grpc.ClientConnInterface, opts ...AuthzClientOption) *ClientImpl {
	client := &ClientImpl{
		clientV1: authzv1.NewAuthzServiceClient(cc),
		tracer:   noop.Tracer{},
	}

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

	return client
}

// -----
// Implementation
// -----

func (c *ClientImpl) check(ctx context.Context, id types.AuthInfo, req *types.CheckRequest) (bool, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.hasAccess")
	defer span.End()

	// TODO idIsServiceAccount is always false here? Can remove this check?
	idIsServiceAccount := types.IsIdentityType(id.GetIdentityType(), types.TypeServiceAccount)
	if !idIsServiceAccount && (req.Name == k6FolderUID || req.Folder == k6FolderUID) {
		return false, nil
	}

	key := checkCacheKey(id.GetSubject(), req)
	res, err := c.getCachedCheck(ctx, key)
	if err == nil {
		return res, nil
	}

	checkReq := &authzv1.CheckRequest{
		Subject:     id.GetUID(),
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
	verbs := []string{verb}

	// we always map list to get for authz
	// to be backward compatible with access tokens we accept both for now
	if verb == "list" {
		verbs = append(verbs, "get")
	}

	for _, p := range tokenPermissions {
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			continue
		}
		pVerb := parts[1]
		if pVerb != "*" && !slices.Contains(verbs, pVerb) {
			continue
		}

		parts = strings.SplitN(parts[0], "/", 2)
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

	if err := types.ValidateCheckRequest(req); err != nil {
		span.RecordError(err)
		return checkResponseDenied, err
	}

	if err := validateAuthInfo(id, req.Namespace, span); err != nil {
		return checkResponseDenied, err
	}

	span.SetAttributes(attribute.String("subject", id.GetSubject()))
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
		permissions := id.GetTokenPermissions()
		serviceIsAllowedAction := hasPermissionInToken(permissions, req.Group, req.Resource, req.Verb)

		span.SetAttributes(attribute.Int("permissions", len(permissions)))
		span.SetAttributes(attribute.Bool("service_allowed", serviceIsAllowedAction))

		return types.CheckResponse{Allowed: serviceIsAllowedAction}, nil
	}

	// Only check the service permissions if the access token check is enabled
	permissions := id.GetTokenDelegatedPermissions()
	serviceIsAllowedAction := hasPermissionInToken(permissions, req.Group, req.Resource, req.Verb)

	span.SetAttributes(attribute.Int("delegated_permissions", len(permissions)))
	span.SetAttributes(attribute.Bool("service_allowed", serviceIsAllowedAction))

	if !serviceIsAllowedAction {
		return checkResponseDenied, nil
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
		Subject:     id.GetUID(),
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

	if err := types.ValidateListRequest(list); err != nil {
		span.RecordError(err)
		return nil, err
	}

	if err := validateAuthInfo(id, list.Namespace, span); err != nil {
		return nil, err
	}

	span.SetAttributes(attribute.String("namespace", list.Namespace))
	span.SetAttributes(attribute.String("group", list.Group))
	span.SetAttributes(attribute.String("resource", list.Resource))
	span.SetAttributes(attribute.String("verb", list.Verb))

	isService := types.IsIdentityType(id.GetIdentityType(), types.TypeAccessPolicy)
	span.SetAttributes(attribute.Bool("with_user", !isService))

	// No user => check on the service permissions
	if isService {
		if hasPermissionInToken(id.GetTokenPermissions(), list.Group, list.Resource, list.Verb) {
			return allowAllChecker(true), nil
		}
		return denyAllChecker, nil
	}

	// Only check the service permissions if the access token check is enabled
	if !hasPermissionInToken(id.GetTokenDelegatedPermissions(), list.Group, list.Resource, list.Verb) {
		return denyAllChecker, nil
	}

	checker, err := c.compile(ctx, id, &list)
	if err != nil {
		span.RecordError(err)
		return denyAllChecker, err
	}

	return checker.fn(id), nil
}

func validateAuthInfo(info types.AuthInfo, namespace string, span trace.Span) error {
	if info.GetSubject() == "" {
		span.RecordError(ErrMissingAuthInfo)
		return ErrMissingAuthInfo
	}

	if !types.NamespaceMatches(info.GetNamespace(), namespace) {
		// TODO why don't we record namespace error on the span?
		return namespaceMismatchError(info.GetNamespace(), namespace)
	}

	return nil
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

var denyAllChecker = func(name, folder string) bool { return false }

func allowAllChecker(isServiceAccount bool) types.ItemChecker {
	return func(name, folder string) bool {
		if !isServiceAccount && (name == k6FolderUID || folder == k6FolderUID) {
			return false
		}

		return true
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
func (c *itemChecker) fn(id types.AuthInfo) types.ItemChecker {
	idIsSvcAccount := types.IsIdentityType(id.GetIdentityType(), types.TypeServiceAccount)
	if c.All {
		return allowAllChecker(idIsSvcAccount)
	}

	if len(c.Items) == 0 && len(c.Folders) == 0 {
		return denyAllChecker
	}

	return func(name, folder string) bool {
		if !idIsSvcAccount && (name == k6FolderUID || folder == k6FolderUID) {
			return false
		}
		return c.Items[name] || c.Folders[folder]
	}
}

func namespaceMismatchError(a, b string) error {
	return fmt.Errorf("%w: got %s but expected %s", ErrNamespaceMissmatch, a, b)
}
