package authz

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/types"
)

func TestHasPermissionInToken(t *testing.T) {
	tests := []struct {
		name             string
		tokenPermissions []string
		group            string
		resource         string
		verb             string
		want             bool
	}{
		{
			name:             "Permission matches group/resource",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "list",
			want:             true,
		},
		{
			name:             "Permission does not match verb",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards:list"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "update",
			want:             false,
		},
		{
			name:             "Permission matches wildcard verb",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards:*"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             true,
		},
		{
			name:             "Invalid permission missing verb",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "list",
			want:             false,
		},
		{
			name:             "Permission on the wrong group",
			tokenPermissions: []string{"other-group.grafana.app/dashboards:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Permission on the wrong resource",
			tokenPermissions: []string{"dashboard.grafana.app/other-resource:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "list",
			want:             false,
		},
		{
			name:             "Permission without group are skipped",
			tokenPermissions: []string{":get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Group level permission",
			tokenPermissions: []string{"dashboard.grafana.app:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "list",
			want:             true,
		},
		{
			name:             "Permission with extra parts does not match group/resource",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards/extra:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Parts need an exact match",
			tokenPermissions: []string{"dashboard.grafana.app/dash:*"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Resource specific permission should not allow access to all resources",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards/dashUID:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasPermissionInToken(tt.tokenPermissions, tt.group, tt.resource, tt.verb)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestClient_Check(t *testing.T) {
	tests := []struct {
		name     string
		caller   *authn.AuthInfo
		req      types.CheckRequest
		folder   string
		checkRes bool
		want     bool
		wantErr  bool
	}{
		{
			name: "No Action",
			req: types.CheckRequest{
				Namespace: "stacks-12",
			},
			wantErr: true,
		},
		{
			name:   "No Caller",
			caller: &authn.AuthInfo{},
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			wantErr: true,
		},
		{
			name: "Missing group",
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Resource:  "dashboards",
				Verb:      "list",
				Name:      "xxyy",
			},
			wantErr: true,
		},
		{
			name: "Missing resource (kind)",
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Verb:      "list",
				Name:      "xxyy",
			},
			wantErr: true,
		},
		{
			name: "Service does not have the action",
			caller: authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
			}),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "Service has the action",
			caller: authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", Permissions: []string{"dashboards.grafana.app/dashboards:list"}},
			}),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: true,
		},
		{
			name: "Service has the action but with an extra part",
			caller: authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", Permissions: []string{"dashboards.grafana.app/dashboards/dashUID:get"}},
			}),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
				Name:      "dashUID",
			},
			want: false,
		},
		{
			name: "Service has the action but in the wrong namespace",
			caller: authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-13", Permissions: []string{"dashboards.grafana.app/dashboards:list"}},
			}),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "On behalf of, id token, service does not have the action",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "On behalf of, id token, service does have the action, but user not",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "On behalf of, id token, service and user have the action",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			checkRes: true,
			want:     true,
		},
		{
			name: "On behalf of, id token, service has the action but with an extra part",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards/dashUID:list"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
				Name:      "dashUID",
			},
			checkRes: true,
			want:     false,
		},
		{
			name: "Service with the permission acting on behalf of a second service",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", Permissions: []string{"dashboards.grafana.app:*"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "secondService"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12", Type: types.TypeAccessPolicy},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: true,
		},
		{
			name: "On behalf of, access token, service does not have the action",
			caller: authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
			}),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "On behalf of, access token, service does have the action, but user not",
			caller: authn.NewAccessTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "On behalf of, access token, service and user have the action",
			caller: authn.NewAccessTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest: authn.AccessTokenClaims{
						DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"},
						Namespace:            "stacks-12",
						Actor: &authn.ActorClaims{
							Subject: "user:1",
							IDTokenClaims: authn.IDTokenClaims{
								Type: types.TypeUser,
							},
						},
					},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			checkRes: true,
			want:     true,
		},
		{
			name: "On behalf of, access token, service has the action but with an extra part",
			caller: authn.NewAccessTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest: authn.AccessTokenClaims{
						Namespace:            "stacks-12",
						DelegatedPermissions: []string{"dashboards.grafana.app/dashboards/dashUID:list"},
						Actor: &authn.ActorClaims{
							Subject: "user:1",
						},
					},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
				Name:      "dashUID",
			},
			checkRes: true,
			want:     false,
		},
		{
			name: "On behalf of, access token, propagated to a second service",
			caller: authn.NewAccessTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest: authn.AccessTokenClaims{
						DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"},
						Namespace:            "stacks-12",
						Actor: &authn.ActorClaims{
							Subject: "secondService",
							Actor: &authn.ActorClaims{
								Subject: "user:1",
								IDTokenClaims: authn.IDTokenClaims{
									Type: types.TypeUser,
								},
							},
						},
					},
				},
			),
			req: types.CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			checkRes: true,
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, authz := setupAccessClient()
			authz.checkRes = &authzv1.CheckResponse{Allowed: tt.checkRes}

			got, err := client.Check(context.Background(), tt.caller, tt.req, tt.folder)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got.Allowed)
		})
	}
}

func TestClient_Check_OnPremFmt(t *testing.T) {
	client, authz := setupAccessClient()

	authz.checkRes = &authzv1.CheckResponse{Allowed: true}
	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest: authn.AccessTokenClaims{
				Namespace:            "default",
				DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "default"},
		},
	)

	req := types.CheckRequest{
		Namespace: "default",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Verb:      "list",
		Name:      "rrss",
	}

	got, err := client.Check(context.Background(), caller, req, "")
	require.NoError(t, err)
	require.True(t, got.Allowed)
}

func TestClient_Check_Cache(t *testing.T) {
	client, authz := setupAccessClient()
	authz.checkRes = &authzv1.CheckResponse{Allowed: true}

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.CheckRequest{
		Namespace: "stacks-12",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Verb:      "list",
		Name:      "rrss",
	}
	folder := ""

	// First call should populate the cache
	got, err := client.Check(context.Background(), caller, req, folder)
	require.NoError(t, err)
	require.True(t, got.Allowed)

	// Check that the cache was populated correctly
	ctrl, _, err := client.getCachedCheck(context.Background(), checkCacheKey("user:1", &req, folder))
	require.NoError(t, err)
	require.True(t, ctrl)

	// Change the response to make sure the cache is used
	authz.checkRes = &authzv1.CheckResponse{Allowed: false}

	// Second call should still be true as we hit the cache
	got, err = client.Check(context.Background(), caller, req, folder)
	require.NoError(t, err)
	require.True(t, got.Allowed)
}

func TestClient_Check_SkipCache(t *testing.T) {
	client, authz := setupAccessClient()
	authz.checkRes = &authzv1.CheckResponse{Allowed: true}

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.CheckRequest{
		Namespace: "stacks-12",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Verb:      "list",
		Name:      "rrss",
	}
	folder := ""

	// First call should populate the cache
	got, err := client.Check(context.Background(), caller, req, folder)
	require.NoError(t, err)
	require.True(t, got.Allowed)

	// Change the response to make sure cache would return different result
	authz.checkRes = &authzv1.CheckResponse{Allowed: false}

	// Second call without SkipCache should still be true (from cache)
	got, err = client.Check(context.Background(), caller, req, folder)
	require.NoError(t, err)
	require.True(t, got.Allowed)

	// Third call WITH SkipCache should be false (bypasses cache)
	req.SkipCache = true
	got, err = client.Check(context.Background(), caller, req, folder)
	require.NoError(t, err)
	require.False(t, got.Allowed)
}

func TestClient_Check_Zookie(t *testing.T) {
	client, authz := setupAccessClient()

	expectedTimestamp := time.Now().Add(-5 * time.Minute).UnixMilli()
	authz.checkRes = &authzv1.CheckResponse{
		Allowed: true,
		Zookie:  &authzv1.Zookie{Timestamp: expectedTimestamp},
	}

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.CheckRequest{
		Namespace: "stacks-12",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Verb:      "list",
	}

	got, err := client.Check(context.Background(), caller, req, "")
	require.NoError(t, err)
	require.True(t, got.Allowed)
	require.NotNil(t, got.Zookie)

	// Verify the zookie has the correct timestamp
	// The zookie should be fresher than a time before expectedTimestamp
	require.True(t, got.Zookie.IsFresherThan(time.UnixMilli(expectedTimestamp-1000)))
	// The zookie should NOT be fresher than a time after expectedTimestamp
	require.False(t, got.Zookie.IsFresherThan(time.UnixMilli(expectedTimestamp+1000)))
}

func TestClient_Compile_Cache(t *testing.T) {
	client, authz := setupAccessClient()

	now := time.Now()

	// User has the action on dash1 and fold1
	authz.listRes = &authzv1.ListResponse{
		All:     false,
		Items:   []string{"dash1"},
		Folders: []string{"fold1"},
		Zookie: &authzv1.Zookie{
			Timestamp: now.UnixMilli(),
		},
	}

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.ListRequest{
		Namespace: "stacks-12",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Verb:      "get",
	}

	// First call should populate the cache
	check, zookie, err := client.Compile(context.Background(), caller, req)
	require.NoError(t, err)
	require.NotNil(t, check)

	// Check the zookie is correct
	require.NotNil(t, zookie)
	require.True(t, zookie.IsFresherThan(now.Add(-time.Minute)))

	// Check that the cache was populated correctly
	ctrl, err := client.getCachedItemChecker(context.Background(), itemCheckerCacheKey("user:1", &req))
	require.NoError(t, err)
	require.False(t, ctrl.All)
	require.True(t, ctrl.Items["dash1"])
	require.True(t, ctrl.Folders["fold1"])

	// Change the response to make sure the cache is used
	authz.listRes = &authzv1.ListResponse{}

	// Second call should still be true as we hit the cache
	check, _, err = client.Compile(context.Background(), caller, req)
	require.NoError(t, err)
	require.NotNil(t, check)
	require.True(t, check("dash1", "fold1"))
}

func TestClient_Compile(t *testing.T) {
	type check struct {
		namespace string
		item      string
		folder    string
	}
	tests := []struct {
		name    string
		caller  *authn.AuthInfo
		listReq types.ListRequest
		listRes *authzv1.ListResponse
		wantErr bool
		wantRes map[check]bool
	}{
		{
			name: "Invalid types.ListRequest",
			listReq: types.ListRequest{
				Group:    "dashboards.grafana.app",
				Resource: "dashboards",
				Verb:     "",
			},
			wantErr: true,
		},
		{
			name:   "Invalid Caller",
			caller: &authn.AuthInfo{},
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
			},
			wantErr: true,
		},
		{
			name: "Caller Namespace Mismatch",
			caller: authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-13"},
			}),
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
			},
			wantErr: true,
		},
		{
			name: "Service has the action",
			caller: authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", Permissions: []string{"dashboards.grafana.app/dashboards:get"}},
			}),
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
			},
			wantRes: map[check]bool{
				{"stacks-12", "dash1", "fold1"}: true,
				{"stacks-12", "dash2", "fold2"}: true,
			},
		},
		{
			name: "Service does not have the action",
			caller: authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
			}),
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
			},
			wantRes: map[check]bool{
				{"stacks-12", "dash1", "fold1"}: false,
			},
		},
		{
			name: "User has the action",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12", Type: types.TypeUser},
				},
			),
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
			},
			listRes: &authzv1.ListResponse{All: true},
			wantRes: map[check]bool{
				{"stacks-12", "dash1", "fold1"}: true,
				{"stacks-12", "dash2", "fold2"}: true,
			},
		},
		{
			name: "User has the action but service does not",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12", Type: types.TypeUser},
				},
			),
			listReq: types.ListRequest{Namespace: "stacks-12", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get"},
			listRes: &authzv1.ListResponse{All: true},
			wantRes: map[check]bool{
				{"stacks-12", "dash1", "fold1"}: false,
				{"stacks-12", "dash2", "fold2"}: false,
				{"stacks-13", "dash2", "fold2"}: false,
			},
		},
		{
			name: "User does not have the action",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12", Type: types.TypeUser},
				},
			),
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
			},
			listRes: &authzv1.ListResponse{},
			wantRes: map[check]bool{
				{"stacks-12", "dash1", "fold1"}: false,
			},
		},
		{
			name: "User has the action on two resources",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12", Type: types.TypeUser},
				},
			),
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
			},
			listRes: &authzv1.ListResponse{Items: []string{"dash1"}, Folders: []string{"fold2"}},
			wantRes: map[check]bool{
				{"stacks-12", "dash1", "fold1"}: true,
				{"stacks-12", "dash2", "fold2"}: true,
				{"stacks-12", "dash2", "fold3"}: false,
			},
		},
		{
			name: "User can't list k6 resources",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"folders.grafana.app/folders:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12", Type: types.TypeUser},
				},
			),
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "folders.grafana.app",
				Resource:  "folders",
				Verb:      "get",
			},
			listRes: &authzv1.ListResponse{Items: []string{"app-k6", "app-k6-child", "another-folder"}},
			wantRes: map[check]bool{
				{"stacks-12", k6FolderUID, ""}:             false,
				{"stacks-12", "k6-app-child", k6FolderUID}: false,
				{"stacks-12", "another-folder", ""}:        true,
			},
		},
		{
			name: "Service account can list k6 resources",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"folders.grafana.app/folders:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "service-account:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12", Type: types.TypeServiceAccount},
				},
			),
			listReq: types.ListRequest{
				Namespace: "stacks-12",
				Group:     "folders.grafana.app",
				Resource:  "folders",
				Verb:      "get",
			},
			listRes: &authzv1.ListResponse{Items: []string{"app-k6", "app-k6-child", "another-folder"}},
			wantRes: map[check]bool{
				{"stacks-12", k6FolderUID, ""}:                               false,
				{"stacks-12", "k6-appauthn/auth_info.go-child", k6FolderUID}: false,
				{"stacks-12", "another-folder", ""}:                          true,
			},
		},
		{
			name: "Access policy with wildcard namespace can list in all namespaces",
			caller: authn.NewAccessTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest: authn.AccessTokenClaims{
						Namespace: "*", Permissions: []string{"folders.grafana.app/folders:get"}},
				},
			),
			listReq: types.ListRequest{
				Group:    "folders.grafana.app",
				Resource: "folders",
				Verb:     "get",
			},
			listRes: &authzv1.ListResponse{Items: []string{"app-k6", "app-k6-child", "another-folder"}},
			wantRes: map[check]bool{
				{"stacks-1", "stack-1", "folder-1"}: true,
				{"stacks-2", "stack2", "folder-2"}:  true,
			},
		},
		{
			name: "User cannot list accross namespaces",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest: authn.AccessTokenClaims{
						Namespace: "*", Permissions: []string{"folders.grafana.app/folders:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{},
					Rest: authn.IDTokenClaims{
						Type:      types.TypeUser,
						Namespace: "stacks-1",
					},
				},
			),
			listReq: types.ListRequest{
				Group:    "folders.grafana.app",
				Resource: "folders",
				Verb:     "get",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, authz := setupAccessClient()
			authz.listRes = tt.listRes

			gotFunc, _, err := client.Compile(context.Background(), tt.caller, tt.listReq)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, gotFunc)
			for check, want := range tt.wantRes {
				got := gotFunc(check.item, check.folder)
				require.Equal(t, want, got)
			}
		})
	}
}

func TestClient_Compile_Zookie(t *testing.T) {
	client, authz := setupAccessClient()

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "*", DelegatedPermissions: []string{"dashboard.grafana.app/dashboards:get"}}},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Type: types.TypeUser, Namespace: "stacks-1"},
		},
	)

	req := types.ListRequest{
		Namespace: "stacks-1",
		Group:     "dashboard.grafana.app",
		Resource:  "dashboards",
		Verb:      "get",
		SkipCache: true,
	}

	t.Run("Recover when list response has no timestamp", func(t *testing.T) {
		authz.listRes = &authzv1.ListResponse{
			Items:   []string{"dash1"},
			Folders: []string{"folder1"},
			Zookie:  nil, // No timestamp provided
		}

		_, zookie, err := client.Compile(context.Background(), caller, req)
		require.NoError(t, err)
		require.NotNil(t, zookie)
		require.True(t, zookie.IsFresherThan(time.Now().Add(-time.Minute)))
	})

	t.Run("Should account for the list response timestamp", func(t *testing.T) {
		authz.listRes = &authzv1.ListResponse{
			Items:   []string{"dash1"},
			Folders: []string{"folder1"},
			Zookie: &authzv1.Zookie{
				Timestamp: time.Now().Add(-time.Hour).UnixMilli(), // Permissions are 1 hour old
			},
		}

		_, zookie, err := client.Compile(context.Background(), caller, req)
		require.NoError(t, err)
		require.NotNil(t, zookie)
		require.False(t, zookie.IsFresherThan(time.Now().Add(-30*time.Minute)))
		require.True(t, zookie.IsFresherThan(time.Now().Add(-2*time.Hour)))
	})
}

func TestBatchCheckRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     types.BatchCheckRequest
		wantErr error
	}{
		{
			name:    "Empty checks is valid",
			req:     types.BatchCheckRequest{Checks: []types.BatchCheckItem{}},
			wantErr: nil,
		},
		{
			name: "Valid request with one check",
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get"},
				},
			},
			wantErr: nil,
		},
		{
			name: "Valid request with exactly 50 checks",
			req: func() types.BatchCheckRequest {
				checks := make([]types.BatchCheckItem, 50)
				for i := 0; i < 50; i++ {
					checks[i] = types.BatchCheckItem{
						CorrelationID: fmt.Sprintf("id-%d", i),
						Group:         "dashboards.grafana.app",
						Resource:      "dashboards",
						Verb:          "get",
					}
				}
				return types.BatchCheckRequest{Checks: checks}
			}(),
			wantErr: nil,
		},
		{
			name: "Too many checks (51)",
			req: func() types.BatchCheckRequest {
				checks := make([]types.BatchCheckItem, 51)
				for i := 0; i < 51; i++ {
					checks[i] = types.BatchCheckItem{
						CorrelationID: fmt.Sprintf("id-%d", i),
						Group:         "dashboards.grafana.app",
						Resource:      "dashboards",
						Verb:          "get",
					}
				}
				return types.BatchCheckRequest{Checks: checks}
			}(),
			wantErr: types.ErrTooManyChecks,
		},
		{
			name: "Empty correlation ID",
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get"},
				},
			},
			wantErr: types.ErrEmptyCorrelationID,
		},
		{
			name: "Duplicate correlation IDs",
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "same-id", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get"},
					{CorrelationID: "same-id", Group: "folders.grafana.app", Resource: "folders", Verb: "list"},
				},
			},
			wantErr: types.ErrDuplicateCorrelationID,
		},
		{
			name: "Missing group",
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "1", Group: "", Resource: "dashboards", Verb: "get"},
				},
			},
			wantErr: types.ErrMissingRequestGroup,
		},
		{
			name: "Missing resource",
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "1", Group: "dashboards.grafana.app", Resource: "", Verb: "get"},
				},
			},
			wantErr: types.ErrMissingRequestResource,
		},
		{
			name: "Missing verb",
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: ""},
				},
			},
			wantErr: types.ErrMissingRequestVerb,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClient_BatchCheck(t *testing.T) {
	tests := []struct {
		name          string
		caller        *authn.AuthInfo
		req           types.BatchCheckRequest
		batchCheckRes *authzv1.BatchCheckResponse
		wantErr       bool
		wantRes       map[string]bool // correlation ID -> allowed
	}{
		{
			name: "Empty request returns empty results",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req:     types.BatchCheckRequest{Checks: []types.BatchCheckItem{}},
			wantErr: false,
			wantRes: map[string]bool{},
		},
		{
			name:   "No caller returns error",
			caller: &authn.AuthInfo{},
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12"},
				},
			},
			wantErr: true,
		},
		{
			name: "Validation error - missing verb",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: ""},
				},
			},
			wantErr: true,
		},
		{
			name: "Single check - allowed",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "check-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12", Name: "dash1"},
				},
			},
			batchCheckRes: &authzv1.BatchCheckResponse{
				Results: map[string]*authzv1.BatchCheckResult{"check-1": {Allowed: true}},
				Zookie:  &authzv1.Zookie{Timestamp: time.Now().UnixMilli()},
			},
			wantErr: false,
			wantRes: map[string]bool{"check-1": true},
		},
		{
			name: "Single check - denied",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "check-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12", Name: "dash1"},
				},
			},
			batchCheckRes: &authzv1.BatchCheckResponse{
				Results: map[string]*authzv1.BatchCheckResult{"check-1": {Allowed: false}},
				Zookie:  &authzv1.Zookie{Timestamp: time.Now().UnixMilli()},
			},
			wantErr: false,
			wantRes: map[string]bool{"check-1": false},
		},
		{
			name: "Multiple checks across different resources",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get", "folders.grafana.app/folders:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "dash-check", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12", Name: "dash1"},
					{CorrelationID: "folder-check", Group: "folders.grafana.app", Resource: "folders", Verb: "get", Namespace: "stacks-12", Name: "folder1"},
				},
			},
			batchCheckRes: &authzv1.BatchCheckResponse{
				Results: map[string]*authzv1.BatchCheckResult{
					"dash-check":   {Allowed: true},
					"folder-check": {Allowed: true},
				},
				Zookie: &authzv1.Zookie{Timestamp: time.Now().UnixMilli()},
			},
			wantErr: false,
			wantRes: map[string]bool{"dash-check": true, "folder-check": true},
		},
		{
			name: "Mixed results - some allowed, some denied",
			caller: authn.NewIDTokenAuthInfo(
				authn.Claims[authn.AccessTokenClaims]{
					Claims: jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get", "folders.grafana.app/folders:get"}},
				},
				&authn.Claims[authn.IDTokenClaims]{
					Claims: jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				},
			),
			req: types.BatchCheckRequest{
				Checks: []types.BatchCheckItem{
					{CorrelationID: "check-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12"},
					{CorrelationID: "check-2", Group: "folders.grafana.app", Resource: "folders", Verb: "get", Namespace: "stacks-12"},
				},
			},
			batchCheckRes: &authzv1.BatchCheckResponse{
				Results: map[string]*authzv1.BatchCheckResult{
					"check-1": {Allowed: true},
					"check-2": {Allowed: false},
				},
				Zookie: &authzv1.Zookie{Timestamp: time.Now().UnixMilli()},
			},
			wantErr: false,
			wantRes: map[string]bool{"check-1": true, "check-2": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, authz := setupAccessClient()
			authz.batchCheckRes = tt.batchCheckRes

			resp, err := client.BatchCheck(context.Background(), tt.caller, tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, resp.Results, len(tt.wantRes))

			for corrID, wantAllowed := range tt.wantRes {
				result, exists := resp.Results[corrID]
				require.True(t, exists, "expected result for correlation ID %s", corrID)
				require.Equal(t, wantAllowed, result.Allowed, "unexpected allowed value for %s", corrID)
			}
		})
	}
}

func TestClient_BatchCheck_Concurrency(t *testing.T) {
	client, authz := setupAccessClient()
	authz.checkRes = &authzv1.CheckResponse{Allowed: true}
	// Force fallback to test concurrent Check calls
	authz.batchCheckErr = status.Error(codes.Unimplemented, "method BatchCheck not implemented")

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	// Create a batch with 20 checks to verify concurrent execution
	checks := make([]types.BatchCheckItem, 20)
	for i := 0; i < 20; i++ {
		checks[i] = types.BatchCheckItem{
			CorrelationID: fmt.Sprintf("check-%d", i),
			Group:         "dashboards.grafana.app",
			Resource:      "dashboards",
			Verb:          "get",
			Namespace:     "stacks-12",
			Name:          fmt.Sprintf("dash-%d", i),
		}
	}

	req := types.BatchCheckRequest{Checks: checks}

	resp, err := client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.Len(t, resp.Results, 20)

	// Verify all results are present and allowed
	for i := 0; i < 20; i++ {
		corrID := fmt.Sprintf("check-%d", i)
		result, exists := resp.Results[corrID]
		require.True(t, exists, "missing result for %s", corrID)
		require.True(t, result.Allowed, "expected allowed for %s", corrID)
		require.NoError(t, result.Error)
	}
}

func TestClient_BatchCheck_Cache(t *testing.T) {
	client, authz := setupAccessClient()
	authz.checkRes = &authzv1.CheckResponse{Allowed: true}
	// Force fallback to test cache behavior through Check calls
	authz.batchCheckErr = status.Error(codes.Unimplemented, "method BatchCheck not implemented")

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.BatchCheckRequest{
		Checks: []types.BatchCheckItem{
			{CorrelationID: "check-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12", Name: "dash1"},
		},
	}

	// First call - should populate cache
	resp, err := client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.True(t, resp.Results["check-1"].Allowed)

	// Change the response to make sure cache is used
	authz.checkRes = &authzv1.CheckResponse{Allowed: false}

	// Second call - should still be true (from cache)
	resp, err = client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.True(t, resp.Results["check-1"].Allowed)
}

func TestClient_BatchCheck_SkipCache(t *testing.T) {
	client, authz := setupAccessClient()
	authz.checkRes = &authzv1.CheckResponse{Allowed: true}
	// Force fallback to test cache behavior through Check calls
	authz.batchCheckErr = status.Error(codes.Unimplemented, "method BatchCheck not implemented")

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.BatchCheckRequest{
		Checks: []types.BatchCheckItem{
			{CorrelationID: "check-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12", Name: "dash1"},
		},
	}

	// First call - should populate cache
	resp, err := client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.True(t, resp.Results["check-1"].Allowed)

	// Change the response
	authz.checkRes = &authzv1.CheckResponse{Allowed: false}

	// Second call without SkipCache - should still be true (from cache)
	resp, err = client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.True(t, resp.Results["check-1"].Allowed)

	// Third call WITH SkipCache - should be false (bypasses cache)
	req.SkipCache = true
	resp, err = client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.False(t, resp.Results["check-1"].Allowed)
}

func TestClient_BatchCheck_Zookie(t *testing.T) {
	client, authz := setupAccessClient()

	expectedTimestamp := time.Now().Add(-5 * time.Minute).UnixMilli()
	authz.checkRes = &authzv1.CheckResponse{
		Allowed: true,
		Zookie:  &authzv1.Zookie{Timestamp: expectedTimestamp},
	}
	// Force fallback to test zookie behavior through Check calls
	authz.batchCheckErr = status.Error(codes.Unimplemented, "method BatchCheck not implemented")

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.BatchCheckRequest{
		Checks: []types.BatchCheckItem{
			{CorrelationID: "check-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12"},
			{CorrelationID: "check-2", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12", Name: "dash2"},
		},
		SkipCache: true,
	}

	resp, err := client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.NotNil(t, resp.Zookie)

	// Verify the zookie has the correct timestamp
	require.True(t, resp.Zookie.IsFresherThan(time.UnixMilli(expectedTimestamp-1000)))
	require.False(t, resp.Zookie.IsFresherThan(time.UnixMilli(expectedTimestamp+1000)))
}

func TestClient_BatchCheck_FallbackToCheckCalls(t *testing.T) {
	// This test verifies that BatchCheck falls back to Check calls
	// when native BatchCheck is not supported
	client, authz := setupAccessClient()
	authz.checkRes = &authzv1.CheckResponse{Allowed: true}
	// Simulate server not supporting BatchCheck
	authz.batchCheckErr = status.Error(codes.Unimplemented, "method BatchCheck not implemented")

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get", "folders.grafana.app/folders:get"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	// Create a batch check request across different resources
	req := types.BatchCheckRequest{
		Checks: []types.BatchCheckItem{
			{CorrelationID: "dash-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12", Name: "dash1"},
			{CorrelationID: "folder-1", Group: "folders.grafana.app", Resource: "folders", Verb: "get", Namespace: "stacks-12", Name: "folder1"},
		},
	}

	resp, err := client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.Len(t, resp.Results, 2)
	require.True(t, resp.Results["dash-1"].Allowed)
	require.True(t, resp.Results["folder-1"].Allowed)
	require.NotNil(t, resp.Zookie)
}

func TestClient_BatchCheck_NativeRPC(t *testing.T) {
	// This test verifies that BatchCheck uses the native RPC when server supports it
	client, authz := setupAccessClient()

	expectedTimestamp := time.Now().UnixMilli()
	authz.batchCheckRes = &authzv1.BatchCheckResponse{
		Results: map[string]*authzv1.BatchCheckResult{
			"dash-1":   {Allowed: true},
			"folder-1": {Allowed: false},
		},
		Zookie: &authzv1.Zookie{Timestamp: expectedTimestamp},
	}

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get", "folders.grafana.app/folders:get"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.BatchCheckRequest{
		Checks: []types.BatchCheckItem{
			{CorrelationID: "dash-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12", Name: "dash1"},
			{CorrelationID: "folder-1", Group: "folders.grafana.app", Resource: "folders", Verb: "get", Namespace: "stacks-12", Name: "folder1"},
		},
	}

	resp, err := client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.Len(t, resp.Results, 2)
	require.True(t, resp.Results["dash-1"].Allowed)
	require.False(t, resp.Results["folder-1"].Allowed)
	require.NotNil(t, resp.Zookie)
	require.True(t, resp.Zookie.IsFresherThan(time.UnixMilli(expectedTimestamp-1000)))
}

func TestClient_BatchCheck_NativeRPC_WithError(t *testing.T) {
	// This test verifies that BatchCheck properly handles error responses from native RPC
	client, authz := setupAccessClient()

	authz.batchCheckRes = &authzv1.BatchCheckResponse{
		Results: map[string]*authzv1.BatchCheckResult{
			"check-1": {Allowed: false, Error: "namespace mismatch"},
		},
		Zookie: &authzv1.Zookie{Timestamp: time.Now().UnixMilli()},
	}

	caller := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"}},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		},
	)

	req := types.BatchCheckRequest{
		Checks: []types.BatchCheckItem{
			{CorrelationID: "check-1", Group: "dashboards.grafana.app", Resource: "dashboards", Verb: "get", Namespace: "stacks-12"},
		},
	}

	resp, err := client.BatchCheck(context.Background(), caller, req)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.False(t, resp.Results["check-1"].Allowed)
	require.Error(t, resp.Results["check-1"].Error)
	require.Contains(t, resp.Results["check-1"].Error.Error(), "namespace mismatch")
}

func setupAccessClient() (*ClientImpl, *FakeAuthzServiceClient) {
	fakeClient := &FakeAuthzServiceClient{}
	return &ClientImpl{
		clientV1: fakeClient,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("noopTracer"),
	}, fakeClient
}

type FakeAuthzServiceClient struct {
	checkRes      *authzv1.CheckResponse
	listRes       *authzv1.ListResponse
	batchCheckRes *authzv1.BatchCheckResponse
	batchCheckErr error
}

func (f *FakeAuthzServiceClient) Check(ctx context.Context, in *authzv1.CheckRequest, opts ...grpc.CallOption) (*authzv1.CheckResponse, error) {
	return f.checkRes, nil
}

func (f *FakeAuthzServiceClient) List(ctx context.Context, in *authzv1.ListRequest, opts ...grpc.CallOption) (*authzv1.ListResponse, error) {
	return f.listRes, nil
}

func (f *FakeAuthzServiceClient) BatchCheck(ctx context.Context, in *authzv1.BatchCheckRequest, opts ...grpc.CallOption) (*authzv1.BatchCheckResponse, error) {
	if f.batchCheckErr != nil {
		return nil, f.batchCheckErr
	}
	if f.batchCheckRes != nil {
		return f.batchCheckRes, nil
	}
	// Default: build response from checkRes for each item in the request
	results := make(map[string]*authzv1.BatchCheckResult, len(in.Checks))
	for _, check := range in.Checks {
		allowed := false
		if f.checkRes != nil {
			allowed = f.checkRes.Allowed
		}
		results[check.CorrelationId] = &authzv1.BatchCheckResult{Allowed: allowed}
	}
	return &authzv1.BatchCheckResponse{
		Results: results,
		Zookie:  &authzv1.Zookie{Timestamp: time.Now().UnixMilli()},
	}, nil
}
