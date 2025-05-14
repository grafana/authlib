package types

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrNamespaceMissmatch     = errors.New("namespace missmatch")
	ErrMissingRequestGroup    = errors.New("missing request group")
	ErrMissingRequestResource = errors.New("missing request resource")
	ErrMissingRequestVerb     = errors.New("missing request verb")
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

type BatchCheckRequest struct {
	Namespace string
	Items     []BatchCheckItem
}

type BatchCheckItem struct {
	// The requested access verb.
	// this includes get, list, watch, create, update, patch, delete, deletecollection, and proxy,
	// or the lowercased HTTP verb associated with non-API requests (this includes get, put, post, patch, and delete)
	Verb string

	// API group (dashboards.grafana.app)
	Group string

	// ~Kind eg dashboards
	Resource string

	// The specific resource
	// In grafana, this was historically called "UID", but in k8s, it is the name
	Name string

	// Optional subresource
	Subresource string

	// Folder is the parent folder of the requested resource
	Folder string
}

type BatchCheckResponse struct {
	// formatted resource string (group/resource[/subresource]) --> group
	Groups map[string]BatchCheckGroupResponse
}

type BatchCheckGroupResponse struct {
	// map of resource name to allowed
	Items map[string]BatchCheckItemResponse
}

type BatchCheckItemResponse struct {
	Allowed bool
}

type AccessChecker interface {
	// Check checks whether the user can perform the given action for all requests
	Check(ctx context.Context, info AuthInfo, req CheckRequest) (CheckResponse, error)
	BatchCheck(ctx context.Context, info AuthInfo, req BatchCheckRequest) (BatchCheckResponse, error)
}

type ListRequest struct {
	// API group (dashboards.grafana.app)
	Group string

	// ~Kind eg dashboards
	Resource string

	// tenant isolation
	Namespace string

	// Verb is the requested access verb.
	Verb string

	// Optional subresource
	Subresource string
}

// Checks access while iterating within a resource
type ItemChecker func(name, folder string) bool

type AccessLister interface {
	// Compile generates a function to check whether the id has access to items matching a request
	// This is particularly useful when you want to verify access to a list of resources.
	// Returns nil if there is no access to any matching items
	Compile(ctx context.Context, info AuthInfo, req ListRequest) (ItemChecker, error)
}

type AccessClient interface {
	AccessChecker
	AccessLister
}

// A simple client that always returns the same value
func FixedAccessClient(allowed bool) AccessClient {
	return &fixedClient{allowed}
}

type fixedClient struct {
	allowed bool
}

func (n *fixedClient) Check(ctx context.Context, _ AuthInfo, req CheckRequest) (CheckResponse, error) {
	if err := ValidateCheckRequest(req); err != nil {
		return CheckResponse{Allowed: false}, err
	}
	return CheckResponse{Allowed: n.allowed}, nil
}

func (n *fixedClient) BatchCheck(ctx context.Context, _ AuthInfo, req BatchCheckRequest) (BatchCheckResponse, error) {
	batchRes := BatchCheckResponse{
		Groups: make(map[string]BatchCheckGroupResponse),
	}

	for _, item := range req.Items {
		if err := ValidateBatchCheckItem(item); err != nil {
			return BatchCheckResponse{}, err
		}
		groupResource := FormatGroupResource(item.Group, item.Resource, item.Subresource)
		if _, ok := batchRes.Groups[groupResource]; !ok {
			batchRes.Groups[groupResource] = BatchCheckGroupResponse{
				Items: make(map[string]BatchCheckItemResponse),
			}
		}
		batchRes.Groups[groupResource].Items[item.Name] = BatchCheckItemResponse{Allowed: n.allowed}
	}
	return batchRes, nil
}

func (n *fixedClient) Compile(ctx context.Context, _ AuthInfo, req ListRequest) (ItemChecker, error) {
	if err := ValidateListRequest(req); err != nil {
		return nil, err
	}
	return func(name, folder string) bool {
		return n.allowed
	}, nil
}

func ValidateCheckRequest(req CheckRequest) error {
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

func ValidateBatchCheckItem(req BatchCheckItem) error {
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

func ValidateListRequest(req ListRequest) error {
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

func FormatGroupResource(group, resource, subresource string) string {
	b := strings.Builder{}
	b.WriteString(group)
	b.WriteRune('/')
	b.WriteString(resource)

	if subresource != "" {
		b.WriteRune('/')
		b.WriteString(subresource)
	}

	return b.String()
}
