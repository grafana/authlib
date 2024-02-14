package authz

import (
	"context"
	"net/http"
)

// HTTPRequestDoer performs HTTP requests.
// The standard http.Client implements this interface.
type HTTPRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client performs requests to the authorization server.
type Client interface {
	// Search returns the permissions for the given query.
	Search(ctx context.Context, query SearchQuery) (*SearchResponse, error)
}

type EnforcementClient interface {
	// Compile generates a function to check whether the user has access to any scope of a given list of scopes.
	// This is particularly useful when you want to verify access to a list of resources.
	Compile(ctx context.Context, idToken string, action string, kinds ...string) (Checker, error)

	// HasAccess checks whether the user can perform the given action on any of the given resources.
	// If the scope is empty, it checks whether the user can perform the action.
	HasAccess(ctx context.Context, idToken string, action string, resources ...Resource) (bool, error)
}

// Checker checks whether a user has access to any of the provided resources.
type Checker func(resources ...Resource) bool

// ServiceOption allows setting custom parameters during construction.
type ServiceOption func(*EnforcementClientImpl) error

// ClientOption allows setting custom parameters during construction.
type ClientOption func(*ClientImpl) error
type Response[T any] struct {
	Data  *T     `json:"data"`
	Error string `json:"error"`
}

type SearchResponse Response[PermissionsByID]

// PermissionsByID groups permissions (with scopes grouped by action) by user/service-account ID.
// ex: { 1: { "teams:read": ["teams:id:2", "teams:id:3"] }, 3: { "teams:read": ["teams:id:1", "teams:id:3"] } }
type PermissionsByID map[int64]Permissions

// Permissions maps actions to the scopes they can be applied to.
// ex: { "pluginID.users:read": ["pluginID.users:uid:xHuuebS", "pluginID.users:uid:znbGGd"] }
type Permissions map[string][]string

type Config struct {
	GrafanaURL string
	Token      string
	JWKsURL    string
}

// Resource represents a resource in Grafana.
type Resource struct {
	// Kind is the type of resource. Ex: "teams", "dashboards", "datasources"
	Kind string
	// The attribute is required for compatibility with the way scopes are defined in Grafana. Ex: "id", "uid"
	Attr string
	// ID is the unique identifier of the resource. Ex: "2", "YYxUSd7ik", "test-datasource"
	ID string
}

func (r *Resource) Scope() string {
	return r.Kind + ":" + r.Attr + ":" + r.ID
}

// SearchQuery is the query to search for permissions.
type SearchQuery struct {
	ActionPrefix string    `json:"actionPrefix,omitempty" url:"actionPrefix,omitempty"`
	Action       string    `json:"action,omitempty" url:"action,omitempty"`
	Scope        string    `json:"scope,omitempty" url:"scope,omitempty"`
	NamespaceID  string    `json:"namespaceId" url:"namespaceId,omitempty"`
	IdToken      string    `json:"-" url:"-"`
	Resource     *Resource `json:"-" url:"-"`
}

// CustomClaims is a placeholder for any potential additional claims in the id token.
type CustomClaims struct{}
