package authn

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

type testEnv struct {
	authenticator *GrpcAuthenticator
	atVerifier    *fakeAccessTokenVerifier
	idVerifier    *fakeIDTokenVerifier
}

func setupGrpcAuthenticator(t *testing.T) *testEnv {
	env := &testEnv{
		atVerifier: &fakeAccessTokenVerifier{},
		idVerifier: &fakeIDTokenVerifier{},
	}
	env.authenticator = &GrpcAuthenticator{
		atVerifier:   env.atVerifier,
		idVerifier:   env.idVerifier,
		namespaceFmt: CloudNamespaceFormatter,
	}

	return env
}

func TestGrpcAuthenticator_authenticateServie(t *testing.T) {
	tests := []struct {
		name            string
		md              metadata.MD
		initAccessToken initAccessTokenVerifierFake
		want            *Claims[AccessTokenClaims]
		wantErr         error
	}{
		{
			name:    "missing access token",
			md:      metadata.Pairs(),
			wantErr: ErrorMissingAccessToken,
		},
		{
			name:    "invalid access token",
			md:      metadata.Pairs(DefaultAccessTokenMetadataKey, "invalid-access-token"),
			wantErr: ErrorInvalidAccessToken,
		},
		{
			name: "invalid namespace",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initAccessToken: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Rest: AccessTokenClaims{Namespace: "stack-13"},
				}
			},
			wantErr: ErrorInvalidAccessToken,
		},
		{
			name: "invalid subject",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initAccessToken: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: "invalid-subject"},
					Rest:   AccessTokenClaims{Namespace: "stack-12"},
				}
			},
			wantErr: ErrorInvalidAccessToken,
		},
		{
			name: "invalid subject type",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initAccessToken: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(namespaceAPIKey) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "stack-12"},
				}
			},
			wantErr: ErrorInvalidAccessToken,
		},
		{
			name: "valid access token",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initAccessToken: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(namespaceAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "stack-12"},
				}
			},
			want: &Claims[AccessTokenClaims]{
				Claims: &jwt.Claims{Subject: string(namespaceAccessPolicy) + ":3"},
				Rest:   AccessTokenClaims{Namespace: "stack-12"},
			},
		},
		{
			name: "valid access token with wildcard namespace",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initAccessToken: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(namespaceAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				}
			},
			want: &Claims[AccessTokenClaims]{
				Claims: &jwt.Claims{Subject: string(namespaceAccessPolicy) + ":3"},
				Rest:   AccessTokenClaims{Namespace: "*"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupGrpcAuthenticator(t)
			if tt.initAccessToken != nil {
				tt.initAccessToken(env)
			}

			got, err := env.authenticator.authenticateService(context.Background(), 12, tt.md)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, *tt.want.Claims, *got.Claims)
			require.Equal(t, tt.want.Rest, got.Rest)
		})
	}
}

func TestGrpcAuthenticator_authenticateUser(t *testing.T) {
	tests := []struct {
		name        string
		md          metadata.MD
		initIDToken initIDTokenVerifierFake
		want        *Claims[IDTokenClaims]
		wantErr     error
	}{
		{
			name:    "missing id token",
			md:      metadata.Pairs(),
			wantErr: ErrorMissingIDToken,
		},
		{
			name:    "invalid id token",
			md:      metadata.Pairs(DefaultIdTokenMetadataKey, "invalid-id-token"),
			wantErr: ErrorInvalidIDToken,
		},
		{
			name: "invalid namespace",
			md:   metadata.Pairs(DefaultIdTokenMetadataKey, "id-token"),
			initIDToken: func(env *testEnv) {
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Rest: IDTokenClaims{Namespace: "stack-13"},
				}
			},
			wantErr: ErrorInvalidIDToken,
		},
		{
			name: "invalid subject",
			md:   metadata.Pairs(DefaultIdTokenMetadataKey, "id-token"),
			initIDToken: func(env *testEnv) {
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Claims: &jwt.Claims{Subject: "invalid-subject"},
					Rest:   IDTokenClaims{Namespace: "stack-12"},
				}
			},
			wantErr: ErrorInvalidIDToken,
		},
		{
			name: "invalid subject type",
			md:   metadata.Pairs(DefaultIdTokenMetadataKey, "id-token"),
			initIDToken: func(env *testEnv) {
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Claims: &jwt.Claims{Subject: string(namespaceAPIKey) + ":3"},
					Rest:   IDTokenClaims{Namespace: "stack-12"},
				}
			},
			wantErr: ErrorInvalidIDToken,
		},
		{
			name: "valid id token",
			md:   metadata.Pairs(DefaultIdTokenMetadataKey, "id-token"),
			initIDToken: func(env *testEnv) {
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Claims: &jwt.Claims{Subject: string(namespaceUser) + ":3"},
					Rest:   IDTokenClaims{Namespace: "stack-12"},
				}
			},
			want: &Claims[IDTokenClaims]{
				Claims: &jwt.Claims{Subject: string(namespaceUser) + ":3"},
				Rest:   IDTokenClaims{Namespace: "stack-12"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupGrpcAuthenticator(t)
			if tt.initIDToken != nil {
				tt.initIDToken(env)
			}

			got, err := env.authenticator.authenticateUser(context.Background(), 12, tt.md)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, *tt.want.Claims, *got.Claims)
			require.Equal(t, tt.want.Rest, got.Rest)
		})
	}
}

type initIDTokenVerifierFake func(*testEnv)

type fakeIDTokenVerifier struct {
	expectedClaims *Claims[IDTokenClaims]
	expectedError  error
}

func (f *fakeIDTokenVerifier) Verify(ctx context.Context, token string) (*Claims[IDTokenClaims], error) {
	if token != "id-token" {
		return nil, fmt.Errorf("invalid id token")
	}
	return f.expectedClaims, f.expectedError
}

type initAccessTokenVerifierFake func(*testEnv)

type fakeAccessTokenVerifier struct {
	expectedClaims *Claims[AccessTokenClaims]
	expectedError  error
}

func (f *fakeAccessTokenVerifier) Verify(ctx context.Context, token string) (*Claims[AccessTokenClaims], error) {
	if token != "access-token" {
		return nil, fmt.Errorf("invalid access token")
	}
	return f.expectedClaims, f.expectedError
}
