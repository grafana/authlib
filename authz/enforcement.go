package authz

import (
	"context"
	"errors"
	"strings"

	"github.com/grafana/authlib/internal/cache"
)

var (
	ErrTooManyPermissions = errors.New("unexpected number of permissions returned by the server")
)

var _ EnforcementClient = &EnforcementClientImpl{}

type EnforcementClientImpl struct {
	client        client
	queryTemplate *searchQuery
	clientOpts    []clientOption
}

func WithHTTPClient(doer HTTPRequestDoer) ClientOption {
	return func(s *EnforcementClientImpl) error {
		s.clientOpts = append(s.clientOpts, withHTTPClient(doer))
		return nil
	}
}

func WithCache(cache cache.Cache) ClientOption {
	return func(s *EnforcementClientImpl) error {
		s.clientOpts = append(s.clientOpts, withCache(cache))
		return nil
	}
}

// WithSearchByPrefix makes the client search for permissions always using the given prefix.
// This can improve performance when the client is used to check permissions for a single action prefix.
func WithSearchByPrefix(prefix string) ClientOption {
	return func(s *EnforcementClientImpl) error {
		s.queryTemplate = &searchQuery{
			ActionPrefix: prefix,
		}
		return nil
	}
}

func NewEnforcementClient(cfg Config, opt ...ClientOption) (*EnforcementClientImpl, error) {
	s := &EnforcementClientImpl{
		client:        nil,
		queryTemplate: nil,
	}

	for _, o := range opt {
		_ = o(s)
	}

	var err error
	if s.client, err = newClient(cfg, s.clientOpts...); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *EnforcementClientImpl) fetchPermissions(ctx context.Context,
	idToken string, action string, resources ...Resource) (permissions, error) {
	var query searchQuery

	if s.queryTemplate != nil && s.queryTemplate.ActionPrefix != "" &&
		strings.HasPrefix(action, s.queryTemplate.ActionPrefix) {
		query = *s.queryTemplate
	} else {
		query = searchQuery{Action: action}
		if len(resources) == 1 {
			res := resources[0]
			query.Resource = &res
		}
	}

	query.IdToken = idToken
	searchRes, err := s.client.Search(ctx, query)
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

func (s *EnforcementClientImpl) Compile(ctx context.Context, idToken string,
	action string, kinds ...string) (Checker, error) {
	permissions, err := s.fetchPermissions(ctx, idToken, action)
	if err != nil {
		return noAccessChecker, err
	}

	return compileChecker(permissions, action, kinds...), nil
}

func resourcesKind(resources ...Resource) []string {
	mK := make(map[string]bool, len(resources))
	kinds := make([]string, 0, len(resources))
	for _, r := range resources {
		if !mK[r.Kind] {
			mK[r.Kind] = true
			kinds = append(kinds, r.Kind)
		}
	}
	return kinds
}

func (s *EnforcementClientImpl) HasAccess(ctx context.Context, idToken string,
	action string, resources ...Resource) (bool, error) {
	permissions, err := s.fetchPermissions(ctx, idToken, action, resources...)
	if err != nil {
		return false, err
	}
	kinds := resourcesKind(resources...)
	return compileChecker(permissions, action, kinds...)(resources...), nil
}

func (s *EnforcementClientImpl) LookupResources(ctx context.Context, idToken string, action string) ([]Resource, error) {
	permissions, err := s.fetchPermissions(ctx, idToken, action)
	if err != nil {
		return nil, err
	}

	resources := make([]Resource, 0, len(permissions))
	for gotAction, scopes := range permissions {
		if gotAction != action {
			continue
		}
		for _, scope := range scopes {
			parts := strings.Split(scope, ":")
			if len(parts) != 3 {
				continue
			}
			resources = append(resources, Resource{
				Kind: parts[0],
				Attr: parts[1],
				ID:   parts[2],
			})
		}
	}
	return resources, nil
}
