package authz

import (
	"context"
	"errors"
)

const maxPrefixParts = 3

var (
	ErrTooManyPermissions = errors.New("unexpected number of permissions returned by the server")
)

type EnforcementClientImpl struct {
	client  Client
	preload *SearchQuery
}

func WithPreloadSearch(query SearchQuery) ServiceOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &query
		return nil
	}
}

func WithPreloadPermissions() ServiceOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &SearchQuery{}
		return nil
	}
}

func WithPreloadPrefixedPermissions(prefix string) ServiceOption {
	return func(s *EnforcementClientImpl) error {
		s.preload = &SearchQuery{
			ActionPrefix: prefix,
		}
		return nil
	}
}

func NewEnforcementClient(cfg Config, opt ...ServiceOption) (*EnforcementClientImpl, error) {
	s := &EnforcementClientImpl{}
	for _, o := range opt {
		_ = o(s)
	}

	if s.client == nil {
		var err error
		if s.client, err = NewClient(cfg); err != nil {
			return nil, err
		}
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

func (s *EnforcementClientImpl) Compile(ctx context.Context, idToken string, action string, kinds ...string) (Checker, error) {
	permissions, err := s.fetchPermissions(ctx, idToken, action)
	if err != nil {
		return NoAccessChecker, err
	}

	return CompileChecker(permissions, action, kinds...), nil
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
	return CompileChecker(permissions, action, kinds...)(resources...), nil
}
