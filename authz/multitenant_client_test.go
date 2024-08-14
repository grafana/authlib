package authz

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/claims"
)

func TestNewController(t *testing.T) {
	tests := []struct {
		name string
		resp *authzv1.ReadResponse
		want *controller
	}{
		{
			name: "User does not have action",
			resp: &authzv1.ReadResponse{
				Found: false,
				Data:  []*authzv1.ReadResponse_Data{},
			},
			want: &controller{
				Found: false,
			},
		},
		{
			name: "User has a scopeless action",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{},
			},
			want: &controller{Found: true},
		},
		{
			name: "User has the action",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:uid:1"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{"dashboards:uid:1": true},
				Wildcard: map[string]bool{},
			},
		},
		{
			name: "User has the action on a wildcard",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:*"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{},
				Wildcard: map[string]bool{"dashboards": true},
			},
		},
		{
			name: "User has the action on a wildcard and a specific scope",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:*"}, {Object: "dashboards:uid:1"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{"dashboards:uid:1": true},
				Wildcard: map[string]bool{"dashboards": true},
			},
		},
		{
			name: "User has the action on wildcards of different kinds",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:*"}, {Object: "folders:*"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{},
				Wildcard: map[string]bool{"dashboards": true, "folders": true},
			},
		},
		{
			name: "User has the action on the master wildcard",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "*"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{},
				Wildcard: map[string]bool{"*": true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newController(tt.resp)

			require.Equal(t, tt.want.Found, got.Found)
			require.Len(t, got.Scopes, len(tt.want.Scopes))
			require.Len(t, got.Wildcard, len(tt.want.Wildcard))

			for k, v := range tt.want.Scopes {
				require.Equal(t, v, got.Scopes[k])
			}
			for k, v := range tt.want.Wildcard {
				require.Equal(t, v, got.Wildcard[k])
			}
		})
	}
}

func TestController_Check(t *testing.T) {
	tests := []struct {
		name      string
		ctrl      controller
		resources []Resource
		want      bool
	}{
		{
			name: "User does not have action",
			ctrl: controller{
				Found: false,
			},
			resources: []Resource{},
			want:      false,
		},
		{
			name: "User has a scopeless action",
			ctrl: controller{
				Found: true,
			},
			resources: []Resource{},
			want:      true,
		},
		{
			name: "User has a scopeless action but requested a resource",
			ctrl: controller{
				Found: true,
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      false,
		},
		{
			name: "User has action on a specific scope",
			ctrl: controller{
				Found:  true,
				Scopes: map[string]bool{"dashboards:uid:1": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on a specific scope but not on the requested resource",
			ctrl: controller{
				Found:  true,
				Scopes: map[string]bool{"dashboards:uid:1": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "2"}},
			want:      false,
		},
		{
			name: "User has action on a wildcard",
			ctrl: controller{
				Found:    true,
				Wildcard: map[string]bool{"dashboards": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on a wildcard but not on the requested resource",
			ctrl: controller{
				Found:    true,
				Wildcard: map[string]bool{"dashboards": true},
			},
			resources: []Resource{{Kind: "folders", Attr: "uid", ID: "1"}},
			want:      false,
		},
		{
			name: "User has action on the master wildcard",
			ctrl: controller{
				Found:    true,
				Wildcard: map[string]bool{"*": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on one of the requested resources",
			ctrl: controller{
				Found:    true,
				Scopes:   map[string]bool{"folders:uid:1": true},
				Wildcard: map[string]bool{},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}, {Kind: "folders", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on none of the requested resources",
			ctrl: controller{
				Found:    true,
				Scopes:   map[string]bool{"folders:uid:2": true},
				Wildcard: map[string]bool{},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}, {Kind: "folders", Attr: "uid", ID: "1"}},
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ctrl.Check(tt.resources...)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestLegacyClientImpl_Check(t *testing.T) {
	type readRes struct {
		found           bool
		userPermissions []string
	}

	makeReadResponse := func(res readRes) *authzv1.ReadResponse {
		if !res.found {
			return &authzv1.ReadResponse{Found: false}
		}

		data := make([]*authzv1.ReadResponse_Data, 0, len(res.userPermissions))
		for _, p := range res.userPermissions {
			data = append(data, &authzv1.ReadResponse_Data{Object: p})
		}

		return &authzv1.ReadResponse{
			Found: true,
			Data:  data,
		}
	}

	tests := []struct {
		name    string
		req     CheckRequest
		res     readRes
		want    bool
		wantErr bool
	}{
		{
			name: "No Caller",
			req: CheckRequest{
				Caller:  authn.CallerAuthInfo{},
				StackID: 12,
				Action:  "dashboards:read",
			},
			wantErr: true,
		},
		{
			name: "Service does not have the action",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID: 12,
				Action:  "dashboards:read",
			},
			want: false,
		},
		{
			name: "Service has the action",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-12", Permissions: []string{"dashboards:read"}},
					},
				},
				StackID: 12,
				Action:  "dashboards:read",
			},
			want: true,
		},
		{
			name: "Service has the action but in the wrong namespace",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-13", Permissions: []string{"dashboards:read"}},
					},
				},
				StackID: 12,
				Action:  "dashboards:read",
			},
			want: false,
		},
		{
			name: "On behalf of, service does not have the action",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-12"},
					},
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID: 12,
				Action:  "dashboards:read",
			},
			want: false,
		},
		{
			name: "On behalf of, service does have the action, but user not",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-12", DelegatedPermissions: []string{"dashboards:read"}},
					},
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID: 12,
				Action:  "dashboards:read",
			},
			want: false,
		},
		{
			name: "On behalf of, action check only",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-12", DelegatedPermissions: []string{"dashboards:read"}},
					},
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID: 12,
				Action:  "dashboards:read",
			},
			res:  readRes{found: true},
			want: true,
		},
		{
			name: "On behalf of, action check only, user is in another namespaces",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "*", DelegatedPermissions: []string{"dashboards:read"}},
					},
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-13"},
					},
				},
				StackID: 12,
				Action:  "dashboards:read",
			},
			want: false,
		},
		{
			name: "On behalf of, user has the action on another resource",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-12", DelegatedPermissions: []string{"dashboards:read"}},
					},
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID:  12,
				Action:   "dashboards:read",
				Resource: &Resource{Kind: "dashboards", Attr: "uid", ID: "1"},
			},
			res:  readRes{found: true, userPermissions: []string{"dashboards:uid:2"}},
			want: false,
		},
		{
			name: "On behalf of, user has the action on the resource",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-12", DelegatedPermissions: []string{"dashboards:read"}},
					},
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID:  12,
				Action:   "dashboards:read",
				Resource: &Resource{Kind: "dashboards", Attr: "uid", ID: "1"},
			},
			res:  readRes{found: true, userPermissions: []string{"dashboards:uid:1"}},
			want: true,
		},
		{
			name: "On behalf of, user has the action on the contextual resource",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stack-12", DelegatedPermissions: []string{"dashboards:read"}},
					},
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID:    12,
				Action:     "dashboards:read",
				Resource:   &Resource{Kind: "dashboards", Attr: "uid", ID: "1"},
				Contextual: []Resource{{Kind: "folders", Attr: "uid", ID: "2"}, {Kind: "folders", Attr: "uid", ID: "1"}},
			},
			res:  readRes{found: true, userPermissions: []string{"folders:uid:1"}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, authz := setupLegacyClient()
			authz.res = makeReadResponse(tt.res)

			got, err := client.Check(context.Background(), &tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestLegacyClientImpl_Check_OnPremFmt(t *testing.T) {
	client, authz := setupLegacyClient()
	client.namespaceFmt = claims.OrgNamespaceFormatter

	authz.res = &authzv1.ReadResponse{Found: true, Data: []*authzv1.ReadResponse_Data{{Object: "dashboards:uid:1"}}}

	req := CheckRequest{
		Caller: authn.CallerAuthInfo{
			AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
				Claims: &jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "default", DelegatedPermissions: []string{"dashboards:read"}},
			},
			IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
				Claims: &jwt.Claims{Subject: "user:1"},
				Rest:   authn.IDTokenClaims{Namespace: "default"},
			},
		},
		StackID:  1,
		Action:   "dashboards:read",
		Resource: &Resource{Kind: "dashboards", Attr: "uid", ID: "1"},
	}

	got, err := client.Check(context.Background(), &req)
	require.NoError(t, err)
	require.True(t, got)
}

func TestLegacyClientImpl_Check_Cache(t *testing.T) {
	client, authz := setupLegacyClient()
	authz.res = &authzv1.ReadResponse{Found: true, Data: []*authzv1.ReadResponse_Data{{Object: "dashboards:uid:1"}}}

	req := CheckRequest{
		Caller: authn.CallerAuthInfo{
			AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{
				Claims: &jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stack-12", DelegatedPermissions: []string{"dashboards:read"}},
			},
			IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
				Claims: &jwt.Claims{Subject: "user:1"},
				Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
			},
		},
		StackID:  12,
		Action:   "dashboards:read",
		Resource: &Resource{Kind: "dashboards", Attr: "uid", ID: "1"},
	}

	// First call should populate the cache
	got, err := client.Check(context.Background(), &req)
	require.NoError(t, err)
	require.True(t, got)

	// Check that the cache was populated correctly
	ctrl, err := client.getCachedController(context.Background(), controllerCacheKey(12, "user:1", "dashboards:read"))
	require.NoError(t, err)
	require.NotNil(t, ctrl)
	require.True(t, ctrl.Found)
	scopes := map[string]bool{"dashboards:uid:1": true}
	require.Len(t, ctrl.Scopes, len(scopes))
	for k, v := range scopes {
		require.Equal(t, v, ctrl.Scopes[k])
	}

	// Change the response to make sure the cache is used
	authz.res = &authzv1.ReadResponse{Found: false}

	// Second call should still be true as we hit the cache
	got, err = client.Check(context.Background(), &req)
	require.NoError(t, err)
	require.True(t, got)
}

func TestLegacyClientImpl_Check_DisableAccessToken(t *testing.T) {
	type readRes struct {
		found           bool
		userPermissions []string
	}

	makeReadResponse := func(res readRes) *authzv1.ReadResponse {
		if !res.found {
			return &authzv1.ReadResponse{Found: false}
		}

		data := make([]*authzv1.ReadResponse_Data, 0, len(res.userPermissions))
		for _, p := range res.userPermissions {
			data = append(data, &authzv1.ReadResponse_Data{Object: p})
		}

		return &authzv1.ReadResponse{
			Found: true,
			Data:  data,
		}
	}

	tests := []struct {
		name    string
		req     CheckRequest
		res     readRes
		want    bool
		wantErr bool
	}{
		{
			name: "No user assume the service is allowed",
			req: CheckRequest{
				Caller:  authn.CallerAuthInfo{},
				StackID: 12,
				Action:  "dashboards:read",
			},
			want: true,
		},
		{
			name: "User has the action on the resource",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID:  12,
				Action:   "dashboards:read",
				Resource: &Resource{Kind: "dashboards", Attr: "uid", ID: "1"},
			},
			res:  readRes{found: true, userPermissions: []string{"dashboards:uid:1"}},
			want: true,
		},
		{
			name: "User has the action on another resource",
			req: CheckRequest{
				Caller: authn.CallerAuthInfo{
					IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stack-12"},
					},
				},
				StackID:  12,
				Action:   "dashboards:read",
				Resource: &Resource{Kind: "dashboards", Attr: "uid", ID: "1"},
			},
			res:  readRes{found: true, userPermissions: []string{"dashboards:uid:2"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, authz := setupLegacyClient()
			WithDisableAccessTokenLCOption()(client)

			authz.res = makeReadResponse(tt.res)

			got, err := client.Check(context.Background(), &tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func setupLegacyClient() (*LegacyClientImpl, *FakeAuthzServiceClient) {
	fakeClient := &FakeAuthzServiceClient{}
	return &LegacyClientImpl{
		authCfg:      &MultiTenantClientConfig{accessTokenAuthEnabled: true},
		clientV1:     fakeClient,
		cache:        cache.NewLocalCache(cache.Config{}),
		namespaceFmt: claims.CloudNamespaceFormatter,
		tracer:       noop.NewTracerProvider().Tracer("noopTracer"),
	}, fakeClient
}

type FakeAuthzServiceClient struct {
	res *authzv1.ReadResponse
}

func (f *FakeAuthzServiceClient) Read(ctx context.Context, in *authzv1.ReadRequest, opts ...grpc.CallOption) (*authzv1.ReadResponse, error) {
	return f.res, nil
}
