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
	query := s.queryTemplate
	// No preload, create a new search query
	if query == nil || (query.ActionPrefix != "" && !strings.HasPrefix(action, query.ActionPrefix)) {
		query = &searchQuery{
			Action: action,
		}
		if len(resources) == 1 {
			res := resources[0]
			query.Resource = &res
		}
	}
	query.IdToken = idToken

	searchRes, err := s.client.Search(ctx, *query)
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
