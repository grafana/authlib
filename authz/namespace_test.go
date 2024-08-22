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
		name    string
		nsFmt   claims.NamespaceFormatter
		caller  claims.AuthInfo
		wantErr error
	}{
		{
			name:    "missing access token",
			nsFmt:   claims.CloudNamespaceFormatter,
			caller:  &authn.AuthInfo{},
			wantErr: ErrorMissingAccessToken,
		},
		{
			name:  "access token match",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
		},
		{
			name:  "access token wildcard match",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}}),
			},
		},
		{
			name:  "access token mismatch",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-13"}}),
			},
			wantErr: ErrorAccessTokenNamespaceMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAccessChecker(tt.nsFmt)
			require.ErrorIs(t, na.CheckAccess(tt.caller, stackID), tt.wantErr)
		})
	}
}

func TestNamespaceAccessCheckerImpl_ValidateIDTokenOnly(t *testing.T) {
	stackID := int64(12)
	tests := []struct {
		name    string
		nsFmt   claims.NamespaceFormatter
		caller  claims.AuthInfo
		wantErr error
	}{
		{
			name:    "missing id token",
			nsFmt:   claims.CloudNamespaceFormatter,
			caller:  &authn.AuthInfo{},
			wantErr: ErrorMissingIDToken,
		},
		{
			name:  "id token match",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
			},
		},
		{
			name:  "id token mismatch",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-13"}}),
			},
			wantErr: ErrorIDTokenNamespaceMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAccessChecker(tt.nsFmt, WithIDTokenNamespaceAccessCheckerOption(true), WithDisableAccessTokenNamespaceAccessCheckerOption())
			require.ErrorIs(t, na.CheckAccess(tt.caller, stackID), tt.wantErr)
		})
	}
}

func TestNamespaceAccessCheckerImpl_ValidateBoth(t *testing.T) {
	stackID := int64(12)
	tests := []struct {
		name    string
		nsFmt   claims.NamespaceFormatter
		caller  claims.AuthInfo
		wantErr error
	}{
		{
			name:  "id token and access token match",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
		},
		{
			name:  "id token and access token wildcard match",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}}),
			},
		},
		{
			name:  "access token mismatch",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-12"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-13"}}),
			},
			wantErr: ErrorAccessTokenNamespaceMismatch,
		},
		{
			name:  "id token mismatch",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				IdentityClaims: authn.NewIdentityClaims(authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stacks-13"}}),
				AccessClaims:   authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
			wantErr: ErrorIDTokenNamespaceMismatch,
		},
		{
			name:  "id token missing but not required",
			nsFmt: claims.CloudNamespaceFormatter,
			caller: &authn.AuthInfo{
				AccessClaims: authn.NewAccessClaims(authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stacks-12"}}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAccessChecker(tt.nsFmt, WithIDTokenNamespaceAccessCheckerOption(false))
			require.ErrorIs(t, na.CheckAccess(tt.caller, stackID), tt.wantErr)
		})
	}
}

func TestMetadataStackIDExtractor(t *testing.T) {
	key := "X-stacks-ID"
	tests := []struct {
		name string
		init func(context.Context) context.Context
		want int64
		err  error
	}{
		{
			name: "missing metadata",
			err:  ErrorMissingMetadata,
		},
		{
			name: "missing stack ID metadata",
			init: func(ctx context.Context) context.Context {
				return metadata.NewIncomingContext(ctx, metadata.MD{})
			},
			err: ErrorMissingMetadata,
		},
		{
			name: "invalid stack ID",
			init: func(ctx context.Context) context.Context {
				return metadata.NewIncomingContext(ctx, metadata.Pairs(key, "invalid"))
			},
			err: ErrorInvalidStackID,
		},
		{
			name: "valid stack ID",
			init: func(ctx context.Context) context.Context {
				return metadata.NewIncomingContext(ctx, metadata.Pairs(key, "12"))
			},
			want: 12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.init != nil {
				ctx = tt.init(ctx)
			}
			stackID, err := MetadataStackIDExtractor(key)(ctx)
			require.Equal(t, tt.want, stackID)
			require.ErrorIs(t, err, tt.err)
		})
	}
}
