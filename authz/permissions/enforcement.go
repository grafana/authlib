package permissions

import (
	"context"
	"errors"
	"strings"

	"github.com/grafana/authlib/authz"
	"github.com/grafana/authlib/authz/api"
)

const maxPrefixParts = 3

var (
	ErrTooManyPermissions = errors.New("unexpected number of permissions returned by the server")
)

type EnforcementClientImpl struct {
	client  api.Client
	preload *api.SearchQuery
}

func WithPreloadSearch(query api.SearchQuery) ServiceOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &query
		return nil
	}
}

func WithPreloadPermissions() ServiceOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &api.SearchQuery{}
		return nil
	}
}

func WithPreloadPrefixedPermissions(prefix string) ServiceOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &api.SearchQuery{
			ActionPrefix: prefix,
		}
		return nil
	}
}

func NewEnforcementClient(client api.Client, opt ...ServiceOption) *EnforcementClientImpl {
	s := &EnforcementClientImpl{
		client: client,
	}
	for _, o := range opt {
		_ = o(s)
	}
	return s
}

// ScopePrefix returns the prefix associated to a given scope
// we assume prefixes are all in the form <resource>:<attribute>:<value>
// ex: "datasources:name:test" returns "datasources:name:"
func ScopePrefix(scope string) string {
	parts := strings.Split(scope, ":")
	// We assume prefixes don't have more than maxPrefixParts parts
	if len(parts) > maxPrefixParts {
		parts = append(parts[:maxPrefixParts], "")
	}
	return strings.Join(parts, ":")
}

func (s *EnforcementClientImpl) fetchPermissions(ctx context.Context, idToken string, action string, resource *authz.Resource) (authz.Permissions, error) {
	searchQuery := s.preload
	// No preload, create a new search query
	if searchQuery == nil {
		searchQuery = &api.SearchQuery{
			Action:   action,
			Resource: resource,
		}
	}
	searchQuery.IdToken = idToken

	searchRes, err := s.client.Search(ctx, *searchQuery)
	if err != nil || searchRes.Data == nil || len(*searchRes.Data) == 0 {
		return nil, err
	}

	if len(*searchRes.Data) != 1 {
		return nil, ErrTooManyPermissions
	}

	for _, perms := range *searchRes.Data {
		return perms, nil
	}
	return nil, nil
}

func (s *EnforcementClientImpl) Compile(ctx context.Context, idToken string, action string, kinds ...string) (Checker, error) {
	permissions, err := s.fetchPermissions(ctx, idToken, action, nil)
	if err != nil {
		return NoAccessChecker, err
	}

	return CompileChecker(permissions, action, kinds...), nil
}

func (s *EnforcementClientImpl) HasAccess(ctx context.Context, idToken string, action string, resource *authz.Resource) (bool, error) {
	permissions, err := s.fetchPermissions(ctx, idToken, action, resource)
	if err != nil {
		return false, err
	}
	if resource == nil {
		return CompileChecker(permissions, action)(), nil
	}
	return CompileChecker(permissions, action, resource.Kind)(*resource), nil
}
