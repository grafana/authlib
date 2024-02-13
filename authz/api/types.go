package api

import (
	"context"
	"net/http"

	"github.com/grafana/authlib/authz"
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

type ClientCfg struct {
	GrafanaURL string
	Token      string
	JWKsURL    string
}

// SearchQuery is the query to search for permissions.
type SearchQuery struct {
	ActionPrefix string          `json:"actionPrefix,omitempty" url:"actionPrefix,omitempty"`
	Action       string          `json:"action,omitempty" url:"action,omitempty"`
	Scope        string          `json:"scope,omitempty" url:"scope,omitempty"`
	NamespaceID  string          `json:"namespaceId" url:"namespaceId,omitempty"`
	IdToken      string          `json:"-" url:"-"`
	Resource     *authz.Resource `json:"-" url:"-"`
}

type SearchResponse authz.Response[PermissionsByID]

// PermissionsByID groups permissions (with scopes grouped by action) by user/service-account ID.
// ex: { 1: { "teams:read": ["teams:id:2", "teams:id:3"] }, 3: { "teams:read": ["teams:id:1", "teams:id:3"] } }
type PermissionsByID map[int64]authz.Permissions

// ClientOption allows setting custom parameters during construction.
type ClientOption func(*ClientImpl) error

// CustomClaims is a placeholder for any potential additional claims in the id token.
type CustomClaims struct{}
