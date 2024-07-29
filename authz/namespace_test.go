package authz

import (
	"testing"

	"github.com/grafana/authlib/authn"
	"github.com/stretchr/testify/require"
)

func TestNamespaceAuthorizerImpl_ValidateAccessTokenOnly(t *testing.T) {
	stackID := int64(12)
	tests := []struct {
		name    string
		nsFmt   authn.NamespaceFormatter
		caller  authn.CallerAuthInfo
		wantErr error
	}{
		{
			name:    "missing access token",
			nsFmt:   authn.CloudNamespaceFormatter,
			caller:  authn.CallerAuthInfo{},
			wantErr: ErrorAccessTokenNamespaceMismatch,
		},
		{
			name:  "access token match",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stack-12"}},
			},
		},
		{
			name:  "access token wildcard match",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}},
			},
		},
		{
			name:  "access token mismatch",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stack-13"}},
			},
			wantErr: ErrorAccessTokenNamespaceMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAuthorizer(tt.nsFmt)
			require.ErrorIs(t, na.Validate(tt.caller, stackID), tt.wantErr)
		})
	}
}

func TestNamespaceAuthorizerImpl_ValidateIDTokenOnly(t *testing.T) {
	stackID := int64(12)
	tests := []struct {
		name    string
		nsFmt   authn.NamespaceFormatter
		caller  authn.CallerAuthInfo
		wantErr error
	}{
		{
			name:    "missing id token",
			nsFmt:   authn.CloudNamespaceFormatter,
			caller:  authn.CallerAuthInfo{},
			wantErr: ErrorMissingIDToken,
		},
		{
			name:  "id token match",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stack-12"}},
			},
		},
		{
			name:  "id token mismatch",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				IDTokenClaims: &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stack-13"}},
			},
			wantErr: ErrorIDTokenNamespaceMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAuthorizer(tt.nsFmt, WithIDTokenNamespaceAuthorizerOption(true), WithDisableAccessTokenNamespaceAuthorizerOption())
			require.ErrorIs(t, na.Validate(tt.caller, stackID), tt.wantErr)
		})
	}
}

func TestNamespaceAuthorizerImpl_ValidateBoth(t *testing.T) {
	stackID := int64(12)
	tests := []struct {
		name    string
		nsFmt   authn.NamespaceFormatter
		caller  authn.CallerAuthInfo
		wantErr error
	}{
		{
			name:  "id token and access token match",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				IDTokenClaims:     &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stack-12"}},
				AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stack-12"}},
			},
		},
		{
			name:  "id token and access token wildcard match",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				IDTokenClaims:     &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stack-12"}},
				AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "*"}},
			},
		},
		{
			name:  "access token mismatch",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				IDTokenClaims:     &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stack-12"}},
				AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stack-13"}},
			},
			wantErr: ErrorAccessTokenNamespaceMismatch,
		},
		{
			name:  "id token mismatch",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				IDTokenClaims:     &authn.Claims[authn.IDTokenClaims]{Rest: authn.IDTokenClaims{Namespace: "stack-13"}},
				AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stack-12"}},
			},
			wantErr: ErrorIDTokenNamespaceMismatch,
		},
		{
			name:  "id token missing but not required",
			nsFmt: authn.CloudNamespaceFormatter,
			caller: authn.CallerAuthInfo{
				AccessTokenClaims: authn.Claims[authn.AccessTokenClaims]{Rest: authn.AccessTokenClaims{Namespace: "stack-12"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na := NewNamespaceAuthorizer(tt.nsFmt, WithIDTokenNamespaceAuthorizerOption(false))
			require.ErrorIs(t, na.Validate(tt.caller, stackID), tt.wantErr)
		})
	}
}
