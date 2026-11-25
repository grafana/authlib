package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/types"
)

// These tests specify the access-policy short-circuit in Check, Compile, and
// BatchCheck. A token permission is group, resource, and verb. It cannot name
// a subresource or a URL path. An access-policy check that sets either field
// must not succeed just because the parent group, resource, and verb match.
//
// The authorization server in these tests allows the parent resource and
// denies every subresource and path. Returning the parent decision for a
// request that names a subresource or path fails the test. Denying locally,
// or querying the server about that same subresource and path and honoring
// the denial, passes.
//
// The tests fail while the client returns the group-resource-verb result for
// those requests.

const (
	subresourceBypassGroup    = "dashboards.grafana.app"
	subresourceBypassResource = "dashboards"
	subresourceBypassVerb     = "get"
	subresourceBypassNS       = "stacks-12"
	subresourceBypassPerm     = "dashboards.grafana.app/dashboards:get"
	sensitiveSubresource      = "permissions"
	sensitivePath             = "/admin/export"
)

func TestAccessPolicyCheckDoesNotAuthorizeSubresourceOrPathFromParentPermission(t *testing.T) {
	cases := []struct {
		name        string
		permissions []string
		verb        string
		subresource string
		path        string
		info        types.AuthInfo
	}{
		{
			name:        "subresource",
			permissions: []string{subresourceBypassPerm},
			verb:        subresourceBypassVerb,
			subresource: sensitiveSubresource,
		},
		{
			name:        "path",
			permissions: []string{subresourceBypassPerm},
			verb:        subresourceBypassVerb,
			path:        sensitivePath,
		},
		{
			name:        "subresource and path",
			permissions: []string{subresourceBypassPerm},
			verb:        subresourceBypassVerb,
			subresource: sensitiveSubresource,
			path:        sensitivePath,
		},
		{
			name:        "list verb satisfied by get still denies subresource",
			permissions: []string{subresourceBypassPerm},
			verb:        "list",
			subresource: sensitiveSubresource,
		},
		{
			name:        "wildcard verb on the resource still denies subresource",
			permissions: []string{"dashboards.grafana.app/dashboards:*"},
			verb:        subresourceBypassVerb,
			subresource: sensitiveSubresource,
		},
		{
			name:        "group permission still denies subresource",
			permissions: []string{"dashboards.grafana.app:get"},
			verb:        subresourceBypassVerb,
			subresource: sensitiveSubresource,
		},
		{
			name:        "nested access-policy identity still denies subresource",
			verb:        subresourceBypassVerb,
			subresource: sensitiveSubresource,
			info:        nestedAccessPolicyInfo(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newSubresourceAuthzClient()
			info := tc.info
			if info == nil {
				info = accessPolicyInfo(tc.permissions)
			}
			requireAccessPolicy(t, info)

			resp, err := client.Check(context.Background(), info, types.CheckRequest{
				Namespace:   subresourceBypassNS,
				Group:       subresourceBypassGroup,
				Resource:    subresourceBypassResource,
				Verb:        tc.verb,
				Name:        "uid-1",
				Subresource: tc.subresource,
				Path:        tc.path,
			}, "folder-1")
			require.NoError(t, err)
			require.Falsef(t, resp.Allowed,
				"Check allowed subresource %q path %q from the parent permission; server was asked %d time(s): %+v",
				tc.subresource, tc.path, len(server.checks), server.checks)
		})
	}
}

func TestAccessPolicyParentCheckStaysAllowed(t *testing.T) {
	client, _ := newSubresourceAuthzClient()
	info := accessPolicyInfo([]string{subresourceBypassPerm})

	resp, err := client.Check(context.Background(), info, types.CheckRequest{
		Namespace: subresourceBypassNS,
		Group:     subresourceBypassGroup,
		Resource:  subresourceBypassResource,
		Verb:      subresourceBypassVerb,
		Name:      "uid-1",
	}, "folder-1")
	require.NoError(t, err)
	require.True(t, resp.Allowed, "parent group/resource/verb permission must stay allowed")
}

func TestAccessPolicyCompileDoesNotAuthorizeSubresourceFromParentPermission(t *testing.T) {
	client, server := newSubresourceAuthzClient()
	info := accessPolicyInfo([]string{subresourceBypassPerm})
	requireAccessPolicy(t, info)

	checker, _, err := client.Compile(context.Background(), info, types.ListRequest{
		Namespace:   subresourceBypassNS,
		Group:       subresourceBypassGroup,
		Resource:    subresourceBypassResource,
		Verb:        subresourceBypassVerb,
		Subresource: sensitiveSubresource,
	})
	require.NoError(t, err)
	require.NotNil(t, checker)
	require.Falsef(t, checker("uid-1", "folder-1"),
		"Compile allowed every name for subresource %q; server lists: %+v", sensitiveSubresource, server.lists)
	require.Falsef(t, checker("uid-2", "folder-2"),
		"Compile allowed a second name for subresource %q", sensitiveSubresource)
}

func TestAccessPolicyCompileParentStaysAllowed(t *testing.T) {
	client, _ := newSubresourceAuthzClient()
	info := accessPolicyInfo([]string{subresourceBypassPerm})

	checker, _, err := client.Compile(context.Background(), info, types.ListRequest{
		Namespace: subresourceBypassNS,
		Group:     subresourceBypassGroup,
		Resource:  subresourceBypassResource,
		Verb:      subresourceBypassVerb,
	})
	require.NoError(t, err)
	require.NotNil(t, checker)
	require.True(t, checker("uid-1", "folder-1"))
}

func TestAccessPolicyBatchCheckDoesNotApplyParentPermissionToSubresourceOrPath(t *testing.T) {
	// Parent is first so an in-request cache keyed only by group, resource,
	// and verb is already filled with an allow before the narrowed checks.
	orders := []struct {
		name   string
		checks []types.BatchCheckItem
	}{
		{
			name: "parent decision cached before subresource and path",
			checks: []types.BatchCheckItem{
				parentBatchItem("parent"),
				subresourceBatchItem("subresource"),
				pathBatchItem("path"),
				bothBatchItem("both"),
			},
		},
		{
			name: "subresource decision cached before parent",
			checks: []types.BatchCheckItem{
				subresourceBatchItem("subresource"),
				pathBatchItem("path"),
				bothBatchItem("both"),
				parentBatchItem("parent"),
			},
		},
	}

	for _, order := range orders {
		t.Run(order.name, func(t *testing.T) {
			client, server := newSubresourceAuthzClient()
			info := accessPolicyInfo([]string{subresourceBypassPerm})
			requireAccessPolicy(t, info)

			resp, err := client.BatchCheck(context.Background(), info, types.BatchCheckRequest{
				Namespace: subresourceBypassNS,
				Checks:    order.checks,
			})
			require.NoError(t, err)
			requireBatchDecision(t, resp, "parent", true)
			requireBatchDecision(t, resp, "subresource", false)
			requireBatchDecision(t, resp, "path", false)
			requireBatchDecision(t, resp, "both", false)
			// The server allows only an empty subresource and path. Asking it
			// about the parent, then returning that allow for a narrowed
			// check, fails the decisions above.
			t.Logf("authorization server batches: %d", len(server.batches))
		})
	}
}

func TestFilterAuthorizedDoesNotYieldAccessPolicySubresource(t *testing.T) {
	client, _ := newSubresourceAuthzClient()
	info := accessPolicyInfo([]string{subresourceBypassPerm})
	requireAccessPolicy(t, info)
	ctx := types.WithAuthInfo(context.Background(), info)

	items := []testItem{
		{name: "parent-item", folder: "folder-1", namespace: subresourceBypassNS},
		{name: "subresource-item", folder: "folder-1", namespace: subresourceBypassNS},
	}
	extract := func(item testItem) BatchCheckItem {
		subresource := ""
		if item.name == "subresource-item" {
			subresource = sensitiveSubresource
		}
		return BatchCheckItem{
			Name:        item.name,
			Folder:      item.folder,
			Verb:        subresourceBypassVerb,
			Group:       subresourceBypassGroup,
			Resource:    subresourceBypassResource,
			Subresource: subresource,
			Namespace:   item.namespace,
		}
	}

	var yielded []string
	for item, err := range FilterAuthorized(ctx, client, toSeq(items), extract) {
		require.NoError(t, err)
		yielded = append(yielded, item.name)
	}
	require.Equal(t, []string{"parent-item"}, yielded)
}

func TestOnBehalfOfCheckHonorsServerDenialOfSubresource(t *testing.T) {
	client, server := newSubresourceAuthzClient()
	info := onBehalfOfUserInfo()

	resp, err := client.Check(context.Background(), info, types.CheckRequest{
		Namespace:   subresourceBypassNS,
		Group:       subresourceBypassGroup,
		Resource:    subresourceBypassResource,
		Verb:        subresourceBypassVerb,
		Name:        "uid-1",
		Subresource: sensitiveSubresource,
		Path:        sensitivePath,
	}, "folder-1")
	require.NoError(t, err)
	require.False(t, resp.Allowed)
	require.Len(t, server.checks, 1)
	require.Equal(t, sensitiveSubresource, server.checks[0].GetSubresource())
	require.Equal(t, sensitivePath, server.checks[0].GetPath())
	require.Equal(t, subresourceBypassResource, server.checks[0].GetResource())
}

func accessPolicyInfo(permissions []string) types.AuthInfo {
	return authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
		Claims: jwt.Claims{Subject: "access-policy:caller"},
		Rest: authn.AccessTokenClaims{
			Namespace:   subresourceBypassNS,
			Permissions: permissions,
		},
	})
}

func nestedAccessPolicyInfo() types.AuthInfo {
	return authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "access-policy:caller"},
			Rest: authn.AccessTokenClaims{
				Namespace:   subresourceBypassNS,
				Permissions: []string{subresourceBypassPerm},
			},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "access-policy:other"},
			Rest: authn.IDTokenClaims{
				Namespace: subresourceBypassNS,
				Type:      types.TypeAccessPolicy,
			},
		},
	)
}

func onBehalfOfUserInfo() types.AuthInfo {
	return authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "access-policy:caller"},
			Rest: authn.AccessTokenClaims{
				Namespace:            subresourceBypassNS,
				DelegatedPermissions: []string{subresourceBypassPerm},
			},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest: authn.IDTokenClaims{
				Namespace: subresourceBypassNS,
				Type:      types.TypeUser,
			},
		},
	)
}

func requireAccessPolicy(t *testing.T, info types.AuthInfo) {
	t.Helper()
	require.Equal(t, types.TypeAccessPolicy, info.GetIdentityType())
}

func parentBatchItem(id string) types.BatchCheckItem {
	return types.BatchCheckItem{
		CorrelationID: id,
		Verb:          subresourceBypassVerb,
		Group:         subresourceBypassGroup,
		Resource:      subresourceBypassResource,
		Name:          "uid-1",
		Folder:        "folder-1",
	}
}

func subresourceBatchItem(id string) types.BatchCheckItem {
	item := parentBatchItem(id)
	item.Subresource = sensitiveSubresource
	return item
}

func pathBatchItem(id string) types.BatchCheckItem {
	item := parentBatchItem(id)
	item.Path = sensitivePath
	return item
}

func bothBatchItem(id string) types.BatchCheckItem {
	item := subresourceBatchItem(id)
	item.Path = sensitivePath
	return item
}

func requireBatchDecision(t *testing.T, resp types.BatchCheckResponse, id string, allowed bool) {
	t.Helper()
	result, ok := resp.Results[id]
	require.Truef(t, ok, "missing batch result %s", id)
	require.NoError(t, result.Error)
	require.Equal(t, allowed, result.Allowed, "batch result %s", id)
}

func newSubresourceAuthzClient() (*ClientImpl, *subresourceAuthzServer) {
	server := &subresourceAuthzServer{}
	client := &ClientImpl{
		clientV1: server,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("noopTracer"),
	}
	return client, server
}

// subresourceAuthzServer allows a check only when both subresource and path
// are empty. Any request that names either field is denied. List allows every
// name only for the parent resource.
type subresourceAuthzServer struct {
	checks  []*authzv1.CheckRequest
	lists   []*authzv1.ListRequest
	batches []*authzv1.BatchCheckRequest
}

func (s *subresourceAuthzServer) Check(_ context.Context, in *authzv1.CheckRequest, _ ...grpc.CallOption) (*authzv1.CheckResponse, error) {
	s.checks = append(s.checks, in)
	return &authzv1.CheckResponse{
		Allowed: in.GetSubresource() == "" && in.GetPath() == "",
		Zookie:  &authzv1.Zookie{Timestamp: 1},
	}, nil
}

func (s *subresourceAuthzServer) List(_ context.Context, in *authzv1.ListRequest, _ ...grpc.CallOption) (*authzv1.ListResponse, error) {
	s.lists = append(s.lists, in)
	return &authzv1.ListResponse{
		All:    in.GetSubresource() == "",
		Zookie: &authzv1.Zookie{Timestamp: 1},
	}, nil
}

func (s *subresourceAuthzServer) BatchCheck(_ context.Context, in *authzv1.BatchCheckRequest, _ ...grpc.CallOption) (*authzv1.BatchCheckResponse, error) {
	s.batches = append(s.batches, in)
	results := make(map[string]*authzv1.BatchCheckResult, len(in.GetChecks()))
	for _, check := range in.GetChecks() {
		results[check.GetCorrelationId()] = &authzv1.BatchCheckResult{
			Allowed: check.GetSubresource() == "" && check.GetPath() == "",
		}
	}
	return &authzv1.BatchCheckResponse{Results: results}, nil
}

func (s *subresourceAuthzServer) GetUserPermissions(context.Context, *authzv1.GetUserPermissionsRequest, ...grpc.CallOption) (authzv1.AuthzService_GetUserPermissionsClient, error) {
	return nil, errors.New("unexpected GetUserPermissions call")
}
