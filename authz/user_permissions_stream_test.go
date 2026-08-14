package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/timestamppb"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/types"
)

func TestClient_GetUserPermissionsRejectsPartialStream(t *testing.T) {
	cacheUntil := time.Now().UTC().Add(30 * time.Second)
	backend := cache.NewLocalCache(cache.Config{})
	fake := &fakeUserPermissionsAuthzClient{stream: &fakeGetUserPermissionsClient{
		responses: []*authzv1.GetUserPermissionsResponse{{
			Permissions: []*authzv1.UserPermission{{Action: "dashboards:read", Scope: "dashboards:*"}},
			CacheUntil:  timestamppb.New(cacheUntil),
		}},
		err: errors.New("stream interrupted"),
	}}
	client := &ClientImpl{
		clientV1: fake,
		cache:    backend,
		tracer:   noop.NewTracerProvider().Tracer("test"),
	}
	caller := newUserPermissionsCaller(nil)

	response, err := client.GetUserPermissions(t.Context(), caller, types.GetUserPermissionsRequest{Namespace: "stacks-12"})

	require.ErrorContains(t, err, "stream interrupted")
	require.Empty(t, response.Permissions)
	_, cacheErr := backend.Get(t.Context(), userPermissionsCacheKey(caller.GetUID(), nil, "stacks-12"))
	require.Error(t, cacheErr)
}

func TestClient_GetUserPermissionsSkipCacheFetchesFreshSnapshot(t *testing.T) {
	cacheUntil := timestamppb.New(time.Now().UTC().Add(30 * time.Second))
	fake := &fakeUserPermissionsAuthzClient{stream: &fakeGetUserPermissionsClient{responses: []*authzv1.GetUserPermissionsResponse{{
		Permissions: []*authzv1.UserPermission{{Action: "dashboards:read", Scope: "dashboards:old"}},
		CacheUntil:  cacheUntil,
	}}}}
	client := &ClientImpl{
		clientV1: fake,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("test"),
	}
	caller := newUserPermissionsCaller(nil)
	request := types.GetUserPermissionsRequest{Namespace: "stacks-12"}
	_, err := client.GetUserPermissions(t.Context(), caller, request)
	require.NoError(t, err)
	fake.stream = &fakeGetUserPermissionsClient{responses: []*authzv1.GetUserPermissionsResponse{{
		Permissions: []*authzv1.UserPermission{{Action: "dashboards:read", Scope: "dashboards:new"}},
		CacheUntil:  cacheUntil,
	}}}

	response, err := client.GetUserPermissions(t.Context(), caller, types.GetUserPermissionsRequest{
		Namespace: "stacks-12",
		SkipCache: true,
	})

	require.NoError(t, err)
	require.Equal(t, []types.Permission{{Action: "dashboards:read", Scope: "dashboards:new"}}, response.Permissions)
	require.Equal(t, 2, fake.calls)
}
