package authn

import (
	"testing"

	"github.com/grafana/authlib/types"
	"github.com/stretchr/testify/assert"
)

func TestGetTokenPermissions(t *testing.T) {
	tests := []struct {
		name           string
		authInfo       *AuthInfo
		expectedResult []string
	}{
		{
			name: "No ID token, return access token permissions",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Rest: AccessTokenClaims{
						Permissions: []string{"read", "write"},
					},
				},
			},
			expectedResult: []string{"read", "write"},
		},
		{
			name: "ID token with non-access policy type, return empty permissions",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Rest: AccessTokenClaims{
						Permissions: []string{"read", "write"},
					},
				},
				id: &Claims[IDTokenClaims]{
					Rest: IDTokenClaims{
						Type: types.TypeUser,
					},
				},
			},
			expectedResult: []string{},
		},
		{
			name: "ID token with access policy type, return access token permissions",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Rest: AccessTokenClaims{
						Permissions: []string{"read", "write"},
					},
				},
				id: &Claims[IDTokenClaims]{
					Rest: IDTokenClaims{
						Type: types.TypeAccessPolicy,
					},
				},
			},
			expectedResult: []string{"read", "write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.authInfo.GetTokenPermissions()
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
