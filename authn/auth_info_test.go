package authn

import (
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
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

func TestGetSubject(t *testing.T) {
	tests := []struct {
		name     string
		authInfo *AuthInfo
		expected string
	}{
		{
			name: "ID token is present, return ID token subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
				},
				id: &Claims[IDTokenClaims]{
					Claims: jwt.Claims{
						Subject: "id_subject",
					},
				},
			},
			expected: "id_subject",
		},
		{
			name: "No ID token, actor is present, return actor subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
					Rest: AccessTokenClaims{
						Actor: &ActorClaims{Subject: "actor_subject"},
					},
				},
				id: nil,
			},
			expected: "actor_subject",
		},
		{
			name: "No ID token, no actor, return access token subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
					Rest: AccessTokenClaims{},
				},
				id: nil,
			},
			expected: "at_subject",
		},
		{
			name: "No ID token, actor is nil, return access token subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
					Rest: AccessTokenClaims{
						Actor: nil,
					},
				},
				id: nil,
			},
			expected: "at_subject",
		},
		{
			name: "No ID token, nested actor level 2, return innermost actor subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
					Rest: AccessTokenClaims{
						Actor: &ActorClaims{
							Subject: "actor1_subject",
							Actor: &ActorClaims{
								Subject: "actor2_subject",
							},
						},
					},
				},
				id: nil,
			},
			expected: "actor2_subject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.authInfo.GetSubject()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TODO(Melendez): Planning to write tests for all the changes in the auth_info.go file,
// but am waiting to confirm that these changes make sense before writing all the tests.
