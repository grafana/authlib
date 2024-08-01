package claims

import "context"

// Needs to play nicely with:
// https://github.com/kubernetes/kubernetes/blob/v1.30.3/staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go#L28

type AccessRequest struct {
	Group     string // API group (dashboards.grafana.app)
	Namespace string // tenant isolation

	// For resource requests, this identifies the resource type
	Resource string // ~Kind eg dashboards
	Name     string // historically UID in grafana, but in k8s "name" is the explicit id

	// Optional subresource
	Subresource string

	// Non-resource requests may reference a generic path
	Path string
}

type AccessClient interface {
	// Compile generates a function to check whether the user has access to any scope of a given list of scopes.
	// This is particularly useful when you want to verify access to a list of resources.
	Compile(ctx context.Context, id AuthInfo, verb string, req ...AccessRequest) (AccessChecker, error)

	// HasAccess checks whether the user can perform the given action on any of the given resources.
	// If the scope is empty, it checks whether the user can perform the action.
	HasAccess(ctx context.Context, id AuthInfo, verb string, req ...AccessRequest) (bool, error)
}

// Fast lookup
type AccessChecker func(resource AccessRequest) bool
