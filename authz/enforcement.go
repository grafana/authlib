package authz

import (
	"context"
	"errors"

	"github.com/grafana/authlib/internal/cache"
)

var (
	ErrTooManyPermissions = errors.New("unexpected number of permissions returned by the server")
)

type EnforcementClientImpl struct {
	client     Client
	preload    *SearchQuery
	clientOpts []clientOption
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

func WithPreloadSearch(query SearchQuery) ClientOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &query
		return nil
	}
}

func WithPreloadPermissions() ClientOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &SearchQuery{}
		return nil
	}
}

func WithPreloadPermissionsByPrefix(prefix string) ClientOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &SearchQuery{
			ActionPrefix: prefix,
		}
		return nil
	}
}

func NewEnforcementClient(cfg Config, opt ...ClientOption) (*EnforcementClientImpl, error) {
	s := &EnforcementClientImpl{
		client:  nil,
		preload: nil,
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

func (s *EnforcementClientImpl) fetchPermissions(ctx context.Context, idToken string, action string, resources ...Resource) (Permissions, error) {
	searchQuery := s.preload
	// No preload, create a new search query
	if searchQuery == nil {
		searchQuery = &SearchQuery{
			Action: action,
		}
		if len(resources) == 1 {
			res := resources[0]
			searchQuery.Resource = &res
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

func (s *EnforcementClientImpl) Compile(ctx context.Context, idToken string, action string, kinds ...string) (checker, error) {
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

func (s *EnforcementClientImpl) HasAccess(ctx context.Context, idToken string, action string, resources ...Resource) (bool, error) {
	permissions, err := s.fetchPermissions(ctx, idToken, action, resources...)
	if err != nil {
		return false, err
	}
	kinds := resourcesKind(resources...)
	return compileChecker(permissions, action, kinds...)(resources...), nil
}
