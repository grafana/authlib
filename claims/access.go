package claims

import "context"

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
	Check(ctx context.Context, id AuthInfo, req CheckRequest) (CheckResponse, error)
}

type ListRequest struct {
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

	// Optional subresource
	Subresource string
}

// TODO: Should the namespace be specified in the request instead.
// I don't think we'll be able to Compile over multiple namespaces.
// Checks access while iterating within a resource
type ItemChecker func(namespace string, name string) bool

type AccessClient interface {
	AccessChecker

	// Compile generates a function to check whether the id has access to items matching a request
	// This is particularly useful when you want to verify access to a list of resources.
	// Returns nil if there is no access to any matching items
	Compile(ctx context.Context, id AuthInfo, req ListRequest) (ItemChecker, error)
}
