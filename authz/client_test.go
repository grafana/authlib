package authz

import (
	"context"
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

			got, err := client.Check(context.Background(), tt.caller, tt.req)
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

	got, err := client.Check(context.Background(), caller, req)
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

	// First call should populate the cache
	got, err := client.Check(context.Background(), caller, req)
	require.NoError(t, err)
	require.True(t, got.Allowed)

	// Check that the cache was populated correctly
	ctrl, err := client.getCachedCheck(context.Background(), checkCacheKey("user:1", &req))
	require.NoError(t, err)
	require.True(t, ctrl)

	// Change the response to make sure the cache is used
	authz.checkRes = &authzv1.CheckResponse{Allowed: false}

	// Second call should still be true as we hit the cache
	got, err = client.Check(context.Background(), caller, req)
	require.NoError(t, err)
	require.True(t, got.Allowed)
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
	nowZookie := &authzv1.Zookie{Timestamp: time.Now().UnixMilli()}
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
			listRes: &authzv1.ListResponse{All: true, Zookie: nowZookie},
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
			listRes: &authzv1.ListResponse{All: true, Zookie: nowZookie},
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
			listRes: &authzv1.ListResponse{Zookie: nowZookie},
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
			listRes: &authzv1.ListResponse{Items: []string{"dash1"}, Folders: []string{"fold2"}, Zookie: nowZookie},
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
			listRes: &authzv1.ListResponse{Items: []string{"app-k6", "app-k6-child", "another-folder"}, Zookie: nowZookie},
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
			listRes: &authzv1.ListResponse{Items: []string{"app-k6", "app-k6-child", "another-folder"}, Zookie: nowZookie},
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
			listRes: &authzv1.ListResponse{Items: []string{"app-k6", "app-k6-child", "another-folder"}, Zookie: nowZookie},
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

func setupAccessClient() (*ClientImpl, *FakeAuthzServiceClient) {
	fakeClient := &FakeAuthzServiceClient{}
	return &ClientImpl{
		clientV1: fakeClient,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("noopTracer"),
	}, fakeClient
}

type FakeAuthzServiceClient struct {
	checkRes *authzv1.CheckResponse
	listRes  *authzv1.ListResponse
}

func (f *FakeAuthzServiceClient) Check(ctx context.Context, in *authzv1.CheckRequest, opts ...grpc.CallOption) (*authzv1.CheckResponse, error) {
	return f.checkRes, nil
}

func (f *FakeAuthzServiceClient) List(ctx context.Context, in *authzv1.ListRequest, opts ...grpc.CallOption) (*authzv1.ListResponse, error) {
	return f.listRes, nil
}
