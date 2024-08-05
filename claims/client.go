package claims

import "context"

// Needs to play nicely with:
// https://github.com/kubernetes/kubernetes/blob/v1.30.3/staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go#L28

type AccessRequest struct {
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
}

type AccessClient interface {
	// HasAccess checks whether the user can perform the given action for all requests
	HasAccess(ctx context.Context, id AuthInfo, verb string, req ...AccessRequest) (bool, error)

	// Compile generates a function to check whether the id has access to items matching a request
	// This is particularly useful when you want to verify access to a list of resources.
	// Returns nil if there is no access to any matching items
	Compile(ctx context.Context, id AuthInfo, verb string, req AccessRequest) (AccessChecker, error)
}

// Checks for access to a specific item
type AccessChecker func(namespace string, name string) bool
