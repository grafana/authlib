package authz

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/types"
)

func TestClient_GetUserPermissionsBuffersCompleteSnapshot(t *testing.T) {
	fake := &fakeUserPermissionsAuthzClient{
		stream: &fakeGetUserPermissionsClient{
			responses: []*authzv1.GetUserPermissionsResponse{
				{
					Permissions: []*authzv1.UserPermission{{Action: "dashboards:read", Scope: "dashboards:*"}},
				},
				{
					Permissions: []*authzv1.UserPermission{{Action: "folders:read", Scope: "folders:uid:team"}},
				},
			},
		},
	}
	client := &ClientImpl{
		clientV1: fake,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("test"),
	}

	got, err := client.GetUserPermissions(t.Context(), newUserPermissionsCaller([]string{"team-a", "team-b"}), types.GetUserPermissionsRequest{
		Namespace: "stacks-12",
		SkipCache: true,
	})
	require.NoError(t, err)
	require.Equal(t, types.GetUserPermissionsResponse{
		Permissions: []types.Permission{
			{Action: "dashboards:read", Scope: "dashboards:*"},
			{Action: "folders:read", Scope: "folders:uid:team"},
		},
	}, got)
	require.Equal(t, &authzv1.GetUserPermissionsRequest{
		Subject:   "user:1",
		Namespace: "stacks-12",
		Teams:     []string{"team-a", "team-b"},
		Options:   &authzv1.GetUserPermissionsOptions{Skipcache: true},
	}, fake.req)
}

func TestClient_GetUserPermissionsCachesWithClientDefaultExpiration(t *testing.T) {
	fake := &fakeUserPermissionsAuthzClient{
		stream: &fakeGetUserPermissionsClient{responses: []*authzv1.GetUserPermissionsResponse{{
			Permissions: []*authzv1.UserPermission{{Action: "dashboards:read", Scope: "dashboards:*"}},
		}}},
	}
	backend := &expirationRecordingCache{Cache: cache.NewLocalCache(cache.Config{})}
	client := &ClientImpl{
		clientV1: fake,
		cache:    backend,
		tracer:   noop.NewTracerProvider().Tracer("test"),
	}
	caller := newUserPermissionsCaller(nil)
	req := types.GetUserPermissionsRequest{Namespace: "stacks-12"}

	_, err := client.GetUserPermissions(t.Context(), caller, req)
	require.NoError(t, err)
	require.Equal(t, cache.DefaultExpiration, backend.expiration)
}

func TestClient_GetUserPermissionsReadsCachedSnapshot(t *testing.T) {
	fake := &fakeUserPermissionsAuthzClient{
		stream: &fakeGetUserPermissionsClient{responses: []*authzv1.GetUserPermissionsResponse{{
			Permissions: []*authzv1.UserPermission{{Action: "dashboards:read", Scope: "dashboards:*"}},
		}}},
	}
	client := &ClientImpl{
		clientV1: fake,
		cache:    cache.NewLocalCache(cache.Config{Expiry: time.Minute}),
		tracer:   noop.NewTracerProvider().Tracer("test"),
	}
	caller := newUserPermissionsCaller(nil)
	req := types.GetUserPermissionsRequest{Namespace: "stacks-12"}

	first, err := client.GetUserPermissions(t.Context(), caller, req)
	require.NoError(t, err)
	second, err := client.GetUserPermissions(t.Context(), caller, req)

	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 1, fake.calls)
}

func TestClient_GetUserPermissionsReturnsSnapshotWhenCacheWriteFails(t *testing.T) {
	expected := []types.Permission{{Action: "dashboards:read", Scope: "dashboards:*"}}
	fake := &fakeUserPermissionsAuthzClient{
		stream: &fakeGetUserPermissionsClient{responses: []*authzv1.GetUserPermissionsResponse{{
			Permissions: []*authzv1.UserPermission{{Action: "dashboards:read", Scope: "dashboards:*"}},
		}}},
	}
	client := &ClientImpl{
		clientV1: fake,
		cache: &setErrorCache{
			Cache: cache.NewLocalCache(cache.Config{}),
			err:   errors.New("cache unavailable"),
		},
		tracer: noop.NewTracerProvider().Tracer("test"),
	}

	response, err := client.GetUserPermissions(t.Context(), newUserPermissionsCaller(nil), types.GetUserPermissionsRequest{Namespace: "stacks-12"})

	require.NoError(t, err)
	require.Equal(t, expected, response.Permissions)
}

func TestClient_InvalidateUserPermissionsEvictsCachedSnapshot(t *testing.T) {
	fake := &fakeUserPermissionsAuthzClient{
		stream: userPermissionsResponseStream(),
	}
	client := &ClientImpl{
		clientV1: fake,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("test"),
	}
	caller := newUserPermissionsCaller(nil)
	req := types.GetUserPermissionsRequest{Namespace: "stacks-12"}

	_, err := client.GetUserPermissions(t.Context(), caller, req)
	require.NoError(t, err)
	fake.stream = userPermissionsResponseStream()
	require.NoError(t, client.InvalidateUserPermissions(t.Context(), caller, req))
	_, err = client.GetUserPermissions(t.Context(), caller, req)

	require.NoError(t, err)
	require.Equal(t, 2, fake.calls)
}

func userPermissionsResponseStream() *fakeGetUserPermissionsClient {
	return &fakeGetUserPermissionsClient{responses: []*authzv1.GetUserPermissionsResponse{{
		Permissions: []*authzv1.UserPermission{{Action: "dashboards:read", Scope: "dashboards:*"}},
	}}}
}

func TestClient_GetUserPermissionsRejectsCallerWithoutDelegatedPermission(t *testing.T) {
	fake := &fakeUserPermissionsAuthzClient{
		stream: &fakeGetUserPermissionsClient{responses: []*authzv1.GetUserPermissionsResponse{{}}},
	}
	client := &ClientImpl{
		clientV1: fake,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("test"),
	}

	_, err := client.GetUserPermissions(t.Context(), newTeamsCaller(nil), types.GetUserPermissionsRequest{Namespace: "stacks-12"})
	require.Error(t, err)
	require.Nil(t, fake.req)
}

func newUserPermissionsCaller(teams []string) *authn.AuthInfo {
	return authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest: authn.AccessTokenClaims{
				Namespace:            "stacks-12",
				DelegatedPermissions: []string{"authz.grafana.app/userpermissions:get"},
			},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest: authn.IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "stacks-12",
				Groups:     teams,
			},
		},
	)
}

type fakeUserPermissionsAuthzClient struct {
	authzv1.AuthzServiceClient
	req    *authzv1.GetUserPermissionsRequest
	stream authzv1.AuthzService_GetUserPermissionsClient
	err    error
	calls  int
}

func (f *fakeUserPermissionsAuthzClient) GetUserPermissions(_ context.Context, req *authzv1.GetUserPermissionsRequest, _ ...grpc.CallOption) (authzv1.AuthzService_GetUserPermissionsClient, error) {
	f.req = req
	f.calls++
	return f.stream, f.err
}

type fakeGetUserPermissionsClient struct {
	grpc.ClientStream
	responses []*authzv1.GetUserPermissionsResponse
	err       error
}

type expirationRecordingCache struct {
	cache.Cache
	expiration time.Duration
}

type setErrorCache struct {
	cache.Cache
	err error
}

func (c *setErrorCache) Set(context.Context, string, []byte, time.Duration) error {
	return c.err
}

func (c *expirationRecordingCache) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	c.expiration = expiration
	return c.Cache.Set(ctx, key, value, expiration)
}

func (f *fakeGetUserPermissionsClient) Recv() (*authzv1.GetUserPermissionsResponse, error) {
	if len(f.responses) > 0 {
		resp := f.responses[0]
		f.responses = f.responses[1:]
		return resp, nil
	}
	if f.err != nil {
		err := f.err
		f.err = nil
		return nil, err
	}
	return nil, io.EOF
}

func (f *FakeAuthzServiceClient) GetUserPermissions(context.Context, *authzv1.GetUserPermissionsRequest, ...grpc.CallOption) (authzv1.AuthzService_GetUserPermissionsClient, error) {
	return nil, errors.New("unexpected GetUserPermissions call")
}
