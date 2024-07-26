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

type initEnv func(*testEnv)

func setupGrpcAuthenticator() *testEnv {
	env := &testEnv{
		atVerifier: &fakeAccessTokenVerifier{},
		idVerifier: &fakeIDTokenVerifier{},
	}
	env.authenticator = &GrpcAuthenticator{
		cfg:          &GrpcAuthenticatorConfig{idTokenAuthEnabled: true, idTokenAuthRequired: true},
		atVerifier:   env.atVerifier,
		idVerifier:   env.idVerifier,
		namespaceFmt: CloudNamespaceFormatter,
	}
	setGrpcAuthenticatorCfgDefaults(env.authenticator.cfg)

	return env
}

func TestGrpcAuthenticator_NewGrpcAuthenticator(t *testing.T) {
	t.Run("should return error when missing signing keys URL", func(t *testing.T) {
		ga, err := NewGrpcAuthenticator(&GrpcAuthenticatorConfig{})
		require.ErrorIs(t, err, ErrMissingConfig)
		require.Nil(t, ga)
	})
	t.Run("initialize authenticator with no option", func(t *testing.T) {
		ga, err := NewGrpcAuthenticator(&GrpcAuthenticatorConfig{
			KeyRetrieverConfig: KeyRetrieverConfig{SigningKeysURL: "http://localhost:3000/api/v1/keys"},
		})
		require.NoError(t, err)
		require.NotNil(t, ga)
		require.NotNil(t, ga.keyRetriever)
		require.NotNil(t, ga.atVerifier)
		// Config has default metadata keys
		require.Equal(t, DefaultAccessTokenMetadataKey, ga.cfg.AccessTokenMetadataKey)
		require.Equal(t, DefaultIdTokenMetadataKey, ga.cfg.IDTokenMetadataKey)
		require.Equal(t, DefaultStackIDMetadataKey, ga.cfg.StackIDMetadataKey)
		// ID token authentication is disabled by default
		require.Nil(t, ga.idVerifier)
	})
	t.Run("initialize authenticator with id token option", func(t *testing.T) {
		ga, err := NewGrpcAuthenticator(
			&GrpcAuthenticatorConfig{KeyRetrieverConfig: KeyRetrieverConfig{SigningKeysURL: "http://localhost:3000/api/v1/keys"}},
			WithIDTokenAuthOption(true),
		)
		require.NoError(t, err)
		require.NotNil(t, ga)
		// ID token authentication is enabled
		require.NotNil(t, ga.idVerifier)
		require.True(t, ga.cfg.idTokenAuthEnabled)
		require.True(t, ga.cfg.idTokenAuthRequired)
	})
	t.Run("should not require KeyRetrieverConfig when key retriever is provided", func(t *testing.T) {
		kr := &DefaultKeyRetriever{}
		emptyCfg := &GrpcAuthenticatorConfig{}
		ga, err := NewGrpcAuthenticator(emptyCfg, WithKeyRetrieverOption(kr))
		require.NoError(t, err)
		require.NotNil(t, ga)
		require.Equal(t, kr, ga.keyRetriever)
	})
	t.Run("initialize authenticator with disabled access token", func(t *testing.T) {
		emptyCfg := &GrpcAuthenticatorConfig{}
		ga, err := NewGrpcAuthenticator(emptyCfg, WithDisableAccessTokenAuthOption())
		require.NoError(t, err)
		require.NotNil(t, ga)
		require.Nil(t, ga.atVerifier)
	})
}

func TestGrpcAuthenticator_Authenticate(t *testing.T) {
	tests := []struct {
		name    string
		md      metadata.MD
		initEnv initEnv
		want    CallerAuthInfo
		wantErr error
	}{
		{
			name:    "missing metadata",
			wantErr: ErrorMissingMetadata,
		},
		{
			name:    "missing stack ID",
			md:      metadata.Pairs(),
			wantErr: ErrorMissingMetadata,
		},
		{
			name:    "invalid stack ID",
			md:      metadata.Pairs(DefaultStackIDMetadataKey, "invalid-stack-id"),
			wantErr: ErrorInvalidStackID,
		},
		{
			name:    "missing access token",
			md:      metadata.Pairs(DefaultStackIDMetadataKey, "12"),
			wantErr: ErrorMissingAccessToken,
		},
		{
			name: "missing id token",
			md:   metadata.Pairs(DefaultStackIDMetadataKey, "12", DefaultAccessTokenMetadataKey, "access-token"),
			initEnv: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				}
			},
			wantErr: ErrorMissingIDToken,
		},
		{
			name: "valid authentication",
			md:   metadata.Pairs(DefaultStackIDMetadataKey, "12", DefaultAccessTokenMetadataKey, "access-token", DefaultIdTokenMetadataKey, "id-token"),
			initEnv: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				}
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeUser) + ":3"},
					Rest:   IDTokenClaims{Namespace: "stack-12"},
				}
			},
			want: CallerAuthInfo{
				StackID: 12,
				AccessTokenClaims: Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				},
				IDTokenClaims: &Claims[IDTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeUser) + ":3"},
					Rest:   IDTokenClaims{Namespace: "stack-12"},
				},
			},
		},
		{
			name: "valid service authentication no id token",
			md:   metadata.Pairs(DefaultStackIDMetadataKey, "12", DefaultAccessTokenMetadataKey, "access-token"),
			initEnv: func(env *testEnv) {
				env.authenticator.cfg.idTokenAuthEnabled = true
				env.authenticator.cfg.idTokenAuthRequired = false
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				}
			},
			want: CallerAuthInfo{
				StackID: 12,
				AccessTokenClaims: Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				},
			},
		},
		{
			name: "valid service authentication disable id token verification",
			md:   metadata.Pairs(DefaultStackIDMetadataKey, "12", DefaultAccessTokenMetadataKey, "access-token", DefaultIdTokenMetadataKey, "id-token"),
			initEnv: func(env *testEnv) {
				env.authenticator.cfg.idTokenAuthEnabled = false
				env.authenticator.cfg.idTokenAuthRequired = false
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				}
			},
			want: CallerAuthInfo{
				StackID: 12,
				AccessTokenClaims: Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				},
			},
		},
		{
			name: "valid no authentication when both access and id token are disabled",
			md:   metadata.Pairs(DefaultStackIDMetadataKey, "12", DefaultAccessTokenMetadataKey, "access-token", DefaultIdTokenMetadataKey, "id-token"),
			initEnv: func(env *testEnv) {
				env.authenticator.cfg.accessTokenAuthEnabled = false
				env.authenticator.cfg.idTokenAuthEnabled = false
				env.authenticator.cfg.idTokenAuthRequired = false
			},
			want: CallerAuthInfo{
				StackID:           12,
				AccessTokenClaims: Claims[AccessTokenClaims]{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupGrpcAuthenticator()
			if tt.initEnv != nil {
				tt.initEnv(env)
			}

			ctx := context.Background()
			if tt.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tt.md)
			}

			ctx, err := env.authenticator.Authenticate(ctx)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			got, ok := GetCallerAuthInfoFromContext(ctx)
			require.True(t, ok)

			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.want.StackID, got.StackID)
			if tt.want.AccessTokenClaims.Claims == nil {
				require.Nil(t, got.AccessTokenClaims.Claims)
			} else {
				require.Equal(t, *tt.want.AccessTokenClaims.Claims, *got.AccessTokenClaims.Claims)
			}
			require.Equal(t, tt.want.AccessTokenClaims.Rest, got.AccessTokenClaims.Rest)

			if tt.want.IDTokenClaims == nil {
				require.Nil(t, got.IDTokenClaims)
			} else {
				require.Equal(t, *tt.want.IDTokenClaims.Claims, *got.IDTokenClaims.Claims)
				require.Equal(t, tt.want.IDTokenClaims.Rest, got.IDTokenClaims.Rest)
			}
		})
	}
}

func TestGrpcAuthenticator_authenticateService(t *testing.T) {
	tests := []struct {
		name    string
		md      metadata.MD
		initEnv initEnv
		want    *Claims[AccessTokenClaims]
		wantErr error
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
			initEnv: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Rest: AccessTokenClaims{Namespace: "stack-13"},
				}
			},
			wantErr: ErrorInvalidAccessToken,
		},
		{
			name: "invalid subject",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initEnv: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: "invalid-subject"},
					Rest:   AccessTokenClaims{Namespace: "stack-12"},
				}
			},
			wantErr: ErrorInvalidSubject,
		},
		{
			name: "invalid subject type",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initEnv: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAPIKey) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "stack-12"},
				}
			},
			wantErr: ErrorInvalidSubjectType,
		},
		{
			name: "valid access token",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initEnv: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "stack-12"},
				}
			},
			want: &Claims[AccessTokenClaims]{
				Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
				Rest:   AccessTokenClaims{Namespace: "stack-12"},
			},
		},
		{
			name: "valid access token with wildcard namespace",
			md:   metadata.Pairs(DefaultAccessTokenMetadataKey, "access-token"),
			initEnv: func(env *testEnv) {
				env.atVerifier.expectedClaims = &Claims[AccessTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
					Rest:   AccessTokenClaims{Namespace: "*"},
				}
			},
			want: &Claims[AccessTokenClaims]{
				Claims: &jwt.Claims{Subject: string(typeAccessPolicy) + ":3"},
				Rest:   AccessTokenClaims{Namespace: "*"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupGrpcAuthenticator()
			if tt.initEnv != nil {
				tt.initEnv(env)
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
		name    string
		md      metadata.MD
		initEnv initEnv
		want    *Claims[IDTokenClaims]
		wantErr error
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
			initEnv: func(env *testEnv) {
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Rest: IDTokenClaims{Namespace: "stack-13"},
				}
			},
			wantErr: ErrorInvalidIDToken,
		},
		{
			name: "invalid subject",
			md:   metadata.Pairs(DefaultIdTokenMetadataKey, "id-token"),
			initEnv: func(env *testEnv) {
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Claims: &jwt.Claims{Subject: "invalid-subject"},
					Rest:   IDTokenClaims{Namespace: "stack-12"},
				}
			},
			wantErr: ErrorInvalidSubject,
		},
		{
			name: "invalid subject type",
			md:   metadata.Pairs(DefaultIdTokenMetadataKey, "id-token"),
			initEnv: func(env *testEnv) {
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeAPIKey) + ":3"},
					Rest:   IDTokenClaims{Namespace: "stack-12"},
				}
			},
			wantErr: ErrorInvalidSubjectType,
		},
		{
			name: "valid id token",
			md:   metadata.Pairs(DefaultIdTokenMetadataKey, "id-token"),
			initEnv: func(env *testEnv) {
				env.idVerifier.expectedClaims = &Claims[IDTokenClaims]{
					Claims: &jwt.Claims{Subject: string(typeUser) + ":3"},
					Rest:   IDTokenClaims{Namespace: "stack-12"},
				}
			},
			want: &Claims[IDTokenClaims]{
				Claims: &jwt.Claims{Subject: string(typeUser) + ":3"},
				Rest:   IDTokenClaims{Namespace: "stack-12"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupGrpcAuthenticator()
			if tt.initEnv != nil {
				tt.initEnv(env)
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
