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
		caller   *authn.AuthInfo
		req      CheckRequest
		checkRes bool
		want     bool
		wantErr  bool
	}{
		{
			name: "No Action",
			req: CheckRequest{
				Namespace: "stacks-12",
			},
			wantErr: true,
		},
		{
			name:   "No Caller",
			caller: &authn.AuthInfo{},
			req: CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			wantErr: true,
		},
		{
			name: "Missing group",
			req: CheckRequest{
				Namespace: "stacks-12",
				Resource:  "dashboards",
				Verb:      "list",
				Name:      "xxyy",
			},
			wantErr: true,
		},
		{
			name: "Missing resource (kind)",
			req: CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Verb:      "list",
				Name:      "xxyy",
			},
			wantErr: true,
		},
		{
			name: "Service does not have the action",
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
				}),
			},
			req: CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "Service has the action",
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", Permissions: []string{"dashboards.grafana.app/dashboards:list"}},
				}),
			},
			req: CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: true,
		},
		{
			name: "Service has the action but in the wrong namespace",
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-13", Permissions: []string{"dashboards.grafana.app/dashboards:list"}},
				}),
			},
			req: CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "On behalf of, service does not have the action",
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12"},
				}),
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
					Claims: &jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				}),
			},
			req: CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "On behalf of, service does have the action, but user not",
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
				}),
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
					Claims: &jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				}),
			},
			req: CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: false,
		},
		{
			name: "On behalf of, service and user have the action",
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: "service"},
					Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
				}),
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
					Claims: &jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				}),
			},
			req: CheckRequest{
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
			client, authz := setupLegacyClient()
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

func TestLegacyClientImpl_Check_OnPremFmt(t *testing.T) {
	client, authz := setupLegacyClient()

	authz.checkRes = &authzv1.CheckResponse{Allowed: true}
	caller := &authn.AuthInfo{
		AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
			Claims: &jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "default", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
		}),
		IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
			Claims: &jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "default"},
		}),
	}

	req := CheckRequest{
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

func TestLegacyClientImpl_Check_Cache(t *testing.T) {
	client, authz := setupLegacyClient()
	authz.checkRes = &authzv1.CheckResponse{Allowed: true}

	caller := &authn.AuthInfo{
		AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{
			Claims: &jwt.Claims{Subject: "service"},
			Rest:   authn.AccessTokenClaims{Namespace: "stacks-12", DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:list"}},
		}),
		IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
			Claims: &jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
		}),
	}

	req := CheckRequest{
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

func TestLegacyClientImpl_Check_DisableAccessToken(t *testing.T) {
	tests := []struct {
		name     string
		caller   *authn.AuthInfo
		req      CheckRequest
		checkRes bool
		want     bool
		wantErr  bool
	}{
		{
			name:   "No user assume the service is allowed",
			caller: &authn.AuthInfo{},
			req: CheckRequest{
				Namespace: "stacks-12",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "list",
			},
			want: true,
		},
		{
			name: "User has the action",
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{
					Claims: &jwt.Claims{Subject: "user:1"},
					Rest:   authn.IDTokenClaims{Namespace: "stacks-12"},
				}),
			},
			req: CheckRequest{
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
			client, authz := setupLegacyClient()
			WithDisableAccessTokenClientOption()(client)

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

func setupLegacyClient() (*ClientImpl, *FakeAuthzServiceClient) {
	fakeClient := &FakeAuthzServiceClient{}
	return &ClientImpl{
		authCfg:  &ClientConfig{accessTokenAuthEnabled: true},
		clientV1: fakeClient,
		cache:    cache.NewLocalCache(cache.Config{}),
		tracer:   noop.NewTracerProvider().Tracer("noopTracer"),
	}, fakeClient
}

type FakeAuthzServiceClient struct {
	checkRes *authzv1.CheckResponse
}

func (f *FakeAuthzServiceClient) Check(ctx context.Context, in *authzv1.CheckRequest, opts ...grpc.CallOption) (*authzv1.CheckResponse, error) {
	return f.checkRes, nil
}
