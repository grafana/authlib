package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/claims"
)

func TestNamespaceAccessCheckerImpl_ValidateAccessTokenOnly(t *testing.T) {
	stackID := int64(12)
	tests := []struct {
		name         string
		namespaceFmt claims.NamespaceFormatter
		caller       claims.AuthInfo
		wantErr      error
	}{
		{
			name:         "missing access token",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller:       &authn.AuthInfo{},
			wantErr:      ErrorMissingAccessToken,
		},
		{
			name:         "access token match",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
		},
		{
			name:         "access token match for org checker",
			namespaceFmt: claims.OrgNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "org-12"}}),
			},
		},
		{
			name:         "access token wildcard match",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}}),
			},
		},
		{
			name:         "access token wildcard match for org checker",
			namespaceFmt: claims.OrgNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}}),
			},
		},
		{
			name:         "access token mismatch",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-13"}}),
			},
			wantErr: ErrorAccessTokenNamespaceMismatch,
		},
		{
			name:         "access token mismatch for org checker",
			namespaceFmt: claims.OrgNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "org-13"}}),
			},
			wantErr: ErrorAccessTokenNamespaceMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAccessChecker(tt.namespaceFmt)
			require.ErrorIs(t, na.CheckAccessByID(context.Background(), tt.caller, stackID), tt.wantErr)
		})
	}
}

func TestNamespaceAccessCheckerImpl_ValidateIDTokenOnly(t *testing.T) {
	identifier := int64(12)
	tests := []struct {
		name         string
		namespaceFmt claims.NamespaceFormatter
		caller       claims.AuthInfo
		wantErr      error
	}{
		{
			name:         "missing id token",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller:       &authn.AuthInfo{},
			wantErr:      ErrorMissingIDToken,
		},
		{
			name:         "id token match",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
			},
		},
		{
			name:         "id token match for org checker",
			namespaceFmt: claims.OrgNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "org-12"}}),
			},
		},
		{
			name:         "id token mismatch",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-13"}}),
			},
			wantErr: ErrorIDTokenNamespaceMismatch,
		},
		{
			name:         "id token mismatch for org checker",
			namespaceFmt: claims.OrgNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "org-13"}}),
			},
			wantErr: ErrorIDTokenNamespaceMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAccessChecker(tt.namespaceFmt, WithIDTokenNamespaceAccessCheckerOption(true), WithDisableAccessTokenNamespaceAccessCheckerOption())
			require.ErrorIs(t, na.CheckAccessByID(context.Background(), tt.caller, identifier), tt.wantErr)
		})
	}
}

func TestNamespaceAccessCheckerImpl_ValidateBoth(t *testing.T) {
	identitifer := int64(12)
	tests := []struct {
		name         string
		namespaceFmt claims.NamespaceFormatter
		caller       claims.AuthInfo
		wantErr      error
	}{
		{
			name:         "id token and access token match",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
		},
		{
			name:         "id token and access token (with wildcard namespace) match",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}}),
			},
		},
		{
			name:         "id token and access token match for org checker",
			namespaceFmt: claims.OrgNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "org-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "org-12"}}),
			},
		},
		{
			name:         "id token and access token match deprecated values",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stack-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stack-12"}}),
			},
		},
		{
			name:         "id token (deprecated value) and access token match",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stack-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
		},
		{
			name:         "id token and access token (deprecated value) match",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stack-12"}}),
			},
		},
		{
			name:         "id token and access token wildcard match",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}}),
			},
		},
		{
			name:         "access token mismatch",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-13"}}),
			},
			wantErr: ErrorAccessTokenNamespaceMismatch,
		},
		{
			name:         "id token mismatch",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-13"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
			wantErr: ErrorIDTokenNamespaceMismatch,
		},
		{
			name:         "id token missing but not required",
			namespaceFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAccessChecker(tt.namespaceFmt, WithIDTokenNamespaceAccessCheckerOption(false))
			require.ErrorIs(t, na.CheckAccess(context.Background(), tt.caller, na.namespaceFmt(identitifer)), tt.wantErr)
		})
	}
}

func TestMetadataStackIDExtractor(t *testing.T) {
	key := DefaultNamespaceMetadataKey
	tests := []struct {
		name string
		init func(context.Context) context.Context
		want string
		err  error
	}{
		{
			name: "missing metadata",
			err:  ErrorMissingMetadata,
		},
		{
			name: "missing namespace metadata",
			init: func(ctx context.Context) context.Context {
				return metadata.NewIncomingContext(ctx, metadata.MD{})
			},
			err: ErrorMissingMetadata,
		},
		{
			name: "valid namespace",
			init: func(ctx context.Context) context.Context {
				return metadata.NewIncomingContext(ctx, metadata.Pairs(key, "stacks-12"))
			},
			want: "stacks-12",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.init != nil {
				ctx = tt.init(ctx)
			}
			stackID, err := MetadataNamespaceExtractor(key)(ctx)
			require.Equal(t, tt.want, stackID)
			require.ErrorIs(t, err, tt.err)
		})
	}
}

func TestNamespaceAuthorizationFunc(t *testing.T) {
	// New namespace access checker with ID claims verification
	na := NewNamespaceAccessChecker(claims.CloudNamespaceFormatter, WithIDTokenNamespaceAccessCheckerOption(true))
	nsExtractor := MetadataNamespaceExtractor(DefaultNamespaceMetadataKey)

	authFunc := NamespaceAuthorizationFunc(na, nsExtractor)

	t.Run("missing caller", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(DefaultNamespaceMetadataKey, "stacks-12"))
		err := authFunc(ctx)
		require.ErrorIs(t, err, ErrMissingCaller)
	})

	t.Run("missing namespace", func(t *testing.T) {
		ctx := claims.WithClaims(context.Background(), &authn.AuthInfo{
			AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
		})
		err := authFunc(ctx)
		require.ErrorIs(t, err, ErrorMissingMetadata)
	})

	t.Run("ok", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(DefaultNamespaceMetadataKey, "stacks-12"))
		ctx = claims.WithClaims(ctx, &authn.AuthInfo{
			AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
		})
		err := authFunc(ctx)
		require.NoError(t, err)
	})
}
