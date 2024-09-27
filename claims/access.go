package claims

import "context"

type Contextual struct {
	// ~Kind eg dashboards
	Resource string
	// The specific resource
	// In grafana, this was historically called "UID", but in k8s, it is the name
	Name string
}

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

	// Optional subresource
	Subresource string

	// For non-resource requests, this will be the requested URL path
	Path string

	// tenant isolation
	Namespace string

	// ~Kind eg dashboards
	Resource string

	// The specific resource
	// In grafana, this was historically called "UID", but in k8s, it is the name
	Name string

	// Contextuals are additional resource + name that should be checked.
	// E.g. for dashboards this can be the folder that a it belong to.
	Contextuals []Contextual
}

type CheckResponse struct {
	Allowed bool
}

type ListRequest struct {
	// API group (dashboards.grafana.app)
	Group string

	// Optional subresource
	Subresource string

	// For non-resource requests, this will be the requested URL path
	Path string

	// tenant isolation
	Namespace string

	// ~Kind eg dashboards
	Resource string

	// ContextualResources are additional resources that can be checked to gain access to the resource.
	ContextualResources []string
}

type ListResponse struct {
	// If all is set we can access all resources
	All bool
	// If all is false this will be popublated with all names we can access
	Items []string
}

// Checks access while iterating within a resource
type ItemChecker func(namespace, name string, extra ...Contextual) bool

type AccessClient interface {
	// Check checks whether the identity can perform the given action for all requests
	Check(ctx context.Context, id AuthInfo, req CheckRequest) (*CheckRequest, error)

	// List returns a list of resource names that can be accessed for given action.
	List(ctx context.Context, id AuthInfo, req ListRequest) (*ListResponse, error)

	// Compile generates a function to check whether the id has access to items matching a request
	// This is particularly useful when you want to verify access to a list of resources.
	// Returns nil if there is no access to any matching items
	Compile(ctx context.Context, id AuthInfo, req ListRequest) (ItemChecker, error)
}
