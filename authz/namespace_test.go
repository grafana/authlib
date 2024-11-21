package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/claims"
)

func TestNamespaceAccessChecker(t *testing.T) {
	tests := []struct {
		name      string
		caller    claims.AuthInfo
		wantErr   error
		namespace string
	}{
		{
			name:      "missing access token",
			caller:    &authn.AuthInfo{},
			namespace: claims.CloudNamespaceFormatter(12),
			wantErr:   ErrNamespaceMismatch,
		},
		{
			name:      "access token match",
			caller:    authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			namespace: claims.CloudNamespaceFormatter(12),
		},
		{
			name:      "access token match for org checker",
			caller:    authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "org-12"}}),
			namespace: claims.OrgNamespaceFormatter(12),
		},
		{
			name:      "access token wildcard match",
			caller:    authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}}),
			namespace: claims.CloudNamespaceFormatter(12),
		},
		{
			name:      "access token wildcard match for org checker",
			caller:    authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}}),
			namespace: claims.OrgNamespaceFormatter(12),
		},
		{
			name:      "access token mismatch",
			caller:    authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-13"}}),
			namespace: claims.CloudNamespaceFormatter(12),
			wantErr:   ErrNamespaceMismatch,
		},
		{
			name:      "access token mismatch for org checker",
			caller:    authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "org-13"}}),
			namespace: claims.OrgNamespaceFormatter(12),
			wantErr:   ErrNamespaceMismatch,
		},
		{
			name:      "missing id token",
			namespace: claims.CloudNamespaceFormatter(12),
			caller:    &authn.AuthInfo{},
			wantErr:   ErrNamespaceMismatch,
		},
		{
			name:      "id token match for stack",
			namespace: claims.CloudNamespaceFormatter(12),
			caller:    authn.NewIDTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{}, &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
		},
		{
			name:      "id token mismatch for stack",
			namespace: claims.CloudNamespaceFormatter(12),
			caller:    authn.NewIDTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{}, &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-13"}}),
			wantErr:   ErrNamespaceMismatch,
		},
		{
			name:      "id token match for org",
			namespace: claims.OrgNamespaceFormatter(12),
			caller:    authn.NewIDTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{}, &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "org-12"}}),
		},
		{
			name:      "id token mismatch for org",
			namespace: claims.OrgNamespaceFormatter(12),
			caller:    authn.NewIDTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{}, &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "org-13"}}),
			wantErr:   ErrNamespaceMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAccessChecker()
			require.ErrorIs(t, na.CheckAccess(context.Background(), tt.caller, tt.namespace), tt.wantErr)
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
	na := NewNamespaceAccessChecker()
	nsExtractor := MetadataNamespaceExtractor(DefaultNamespaceMetadataKey)

	authFunc := NamespaceAuthorizationFunc(na, nsExtractor)

	t.Run("missing caller", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(DefaultNamespaceMetadataKey, "stacks-12"))
		err := authFunc(ctx)
		require.ErrorIs(t, err, ErrMissingCaller)
	})

	t.Run("missing namespace", func(t *testing.T) {
		ctx := claims.WithClaims(context.Background(), authn.NewIDTokenAuthInfo(
			authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}},
			&authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}},
		))
		err := authFunc(ctx)
		require.ErrorIs(t, err, ErrorMissingMetadata)
	})

	t.Run("ok", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(DefaultNamespaceMetadataKey, "stacks-12"))
		ctx = claims.WithClaims(ctx, authn.NewIDTokenAuthInfo(
			authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}},
			&authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}},
		))
		err := authFunc(ctx)
		require.NoError(t, err)
	})
}
