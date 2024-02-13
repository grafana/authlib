package permissions

import (
	"context"

	"github.com/grafana/authlib/authz"
)

type EnforcementClient interface {
	// Compile generates a function to check whether the user has access to any scope of a given list of scopes.
	// This is particularly useful when you want to verify access to a list of resources.
	Compile(ctx context.Context, idToken string, action string, kinds ...string) (Checker, error)

	// HasAccess checks whether the user can perform the given action on the given scope.
	// If the scope is empty, it checks whether the user can perform the action.
	HasAccess(ctx context.Context, idToken string, action string, resource *authz.Resource) (bool, error)
}

// Checker checks whether a user has access to any of the provided resources.
type Checker func(resources ...authz.Resource) bool

// ServiceOption allows setting custom parameters during construction.
type ServiceOption func(*EnforcementClientImpl) error
