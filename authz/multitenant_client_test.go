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
)

func TestLegacyClientImpl_Check(t *testing.T) {
	tests := []struct {
		name     string
		req      CheckRequest
		checkRes bool
		want     bool
		wantErr  bool
	}{
		{
			name: "No Caller",
			req: CheckRequest{
				Caller:    &authn.AuthInfo{},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			wantErr: true,
		},
		{
			name: "Service does not have the action",
			req: CheckRequest{
				Caller: &authn.AuthInfo{
					AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
					}),
				},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			want: false,
		},
		{
			name: "Service has the action",
			req: CheckRequest{
				Caller: &authn.AuthInfo{
					AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", Permissions: []string{"dashboards:read"}},
					}),
				},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			want: true,
		},
		{
			name: "Service has the action but in the wrong namespace",
			req: CheckRequest{
				Caller: &authn.AuthInfo{
					AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stacks-13", Permissions: []string{"dashboards:read"}},
					}),
				},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			want: false,
		},
		{
			name: "On behalf of, service does not have the action",
			req: CheckRequest{
				Caller: &authn.AuthInfo{
					AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
					}),
					IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
					}),
				},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			want: false,
		},
		{
			name: "On behalf of, service does have the action, but user not",
			req: CheckRequest{
				Caller: &authn.AuthInfo{
					AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards:read"}},
					}),
					IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
					}),
				},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			want: false,
		},
		{
			name: "On behalf of, service and user have the action",
			req: CheckRequest{
				Caller: &authn.AuthInfo{
					AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
						Claims: &jwt.Claims{Subject: "service"},
						Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards:read"}},
					}),
					IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
					}),
				},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			checkRes: true,
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, authz := setupLegacyClient()
			authz.checkRes = &authzv1.CheckResponse{Allowed: tt.checkRes}

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

	authz.checkRes = &authzv1.CheckResponse{Allowed: true}

	req := CheckRequest{
		Caller: &authn.AuthInfo{
			AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
				Claims: &jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "default", DelegatedPermissions: []string{"dashboards:read"}},
			}),
			IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
				Claims: &jwt.Claims{Subject: "user:1"},
				Rest:   authn.IDTokenClaims{Namespace: "default"},
			}),
		},
		Namespace: "default",
		Action:    "dashboards:read",
		// TODO (gamab): Should we remove the attribute?
		Object: NewString("dashboards:uid:2"),
		Parent: NewString("folders:uid:1"),
	}

	got, err := client.Check(context.Background(), &req)
	require.NoError(t, err)
	require.True(t, got)
}

func TestLegacyClientImpl_Check_Cache(t *testing.T) {
	client, authz := setupLegacyClient()
	authz.checkRes = &authzv1.CheckResponse{Allowed: true}

	req := CheckRequest{
		Caller: &authn.AuthInfo{
			AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
				Claims: &jwt.Claims{Subject: "service"},
				Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards:read"}},
			}),
			IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
				Claims: &jwt.Claims{Subject: "user:1"},
				Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
			}),
		},
		Namespace: "stacks-12",
		Action:    "dashboards:read",
		Object:    NewString("dashboards:uid:2"),
		Parent:    NewString("folders:uid:1"),
	}

	// First call should populate the cache
	got, err := client.Check(context.Background(), &req)
	require.NoError(t, err)
	require.True(t, got)

	// Check that the cache was populated correctly
	ctrl, err := client.getCachedCheck(context.Background(), checkCacheKey("stacks-12", "user:1", "dashboards:read", "dashboards:uid:2", "folders:uid:1"))
	require.NoError(t, err)
	require.True(t, ctrl)

	// Change the response to make sure the cache is used
	authz.checkRes = &authzv1.CheckResponse{Allowed: false}

	// Second call should still be true as we hit the cache
	got, err = client.Check(context.Background(), &req)
	require.NoError(t, err)
	require.True(t, got)
}

func TestLegacyClientImpl_Check_DisableAccessToken(t *testing.T) {
	tests := []struct {
		name     string
		req      CheckRequest
		checkRes bool
		want     bool
		wantErr  bool
	}{
		{
			name: "No user assume the service is allowed",
			req: CheckRequest{
				Caller:    &authn.AuthInfo{},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			want: true,
		},
		{
			name: "User has the action",
			req: CheckRequest{
				Caller: &authn.AuthInfo{
					IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
						Claims: &jwt.Claims{Subject: "user:1"},
						Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
					}),
				},
				Namespace: "stacks-12",
				Action:    "dashboards:read",
			},
			checkRes: true,
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, authz := setupLegacyClient()
			WithDisableAccessTokenLCOption()(client)

			authz.checkRes = &authzv1.CheckResponse{Allowed: tt.checkRes}

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
		authCfg:  &MultiTenantClientConfig{accessTokenAuthEnabled: true},
		clientV1: fakeClient,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("noopTracer"),
	}, fakeClient
}

type FakeAuthzServiceClient struct {
	readRes  *authzv1.ReadResponse
	checkRes *authzv1.CheckResponse
}

func (f *FakeAuthzServiceClient) Read(ctx context.Context, in *authzv1.ReadRequest, opts ...grpc.CallOption) (*authzv1.ReadResponse, error) {
	return f.readRes, nil
}
func (f *FakeAuthzServiceClient) Check(ctx context.Context, in *authzv1.CheckRequest, opts ...grpc.CallOption) (*authzv1.CheckResponse, error) {
	return f.checkRes, nil
}

func NewString(s string) *string {
	return &s
}
