package authn

import (
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/grafana/authlib/types"
	"github.com/stretchr/testify/assert"
)

func TestAuthInfo_NewAccessTokenAuthInfo(t *testing.T) {
	t.Run("without identity actor", func(t *testing.T) {
		at := Claims[AccessTokenClaims]{}
		authInfo := NewAccessTokenAuthInfo(at)
		var nilClaims *Claims[IDTokenClaims]
		assert.Equal(t, nilClaims, authInfo.id)
	})

	t.Run("with identity actor", func(t *testing.T) {
		at := Claims[AccessTokenClaims]{
			Rest: AccessTokenClaims{
				Actor: &ActorClaims{
					Subject: "user-subject",
					IDTokenClaims: IDTokenClaims{
						Type: types.TypeUser,
					},
				},
			},
		}

		authInfo := NewAccessTokenAuthInfo(at)
		assert.Equal(t, "user-subject", authInfo.id.Claims.Subject)
	})
}

func TestAuthInfo_NewIDTokenAuthInfo(t *testing.T) {
	t.Run("default to identity actor if id param is nil", func(t *testing.T) {
		at := Claims[AccessTokenClaims]{
			Rest: AccessTokenClaims{
				Actor: &ActorClaims{
					Subject: "user-subject",
					IDTokenClaims: IDTokenClaims{
						Type: types.TypeUser,
					},
				},
			},
		}

		authInfo := NewIDTokenAuthInfo(at, nil)
		assert.Equal(t, "user-subject", authInfo.id.Claims.Subject)
	})
}

func TestAuthInfo_getIdInfo(t *testing.T) {
	t.Run("without identity actor", func(t *testing.T) {
		at := Claims[AccessTokenClaims]{}
		idInfo := getIdInfo(at)
		var nilClaims *Claims[IDTokenClaims]
		assert.Equal(t, nilClaims, idInfo)
	})

	t.Run("with identity actor", func(t *testing.T) {
		at := Claims[AccessTokenClaims]{
			Rest: AccessTokenClaims{
				Actor: &ActorClaims{
					Subject: "user-subject",
					IDTokenClaims: IDTokenClaims{
						Type: types.TypeUser,
					},
				},
			},
		}

		idInfo := getIdInfo(at)
		assert.Equal(t, "user-subject", idInfo.Claims.Subject)
	})

	t.Run("should not use nested namespace", func(t *testing.T) {
		at := Claims[AccessTokenClaims]{
			Rest: AccessTokenClaims{
				Namespace: "at-namespace",
				Actor: &ActorClaims{
					Subject: "user-subject",
					IDTokenClaims: IDTokenClaims{
						Namespace: "id-namespace",
						Type:      types.TypeUser,
					},
				},
			},
		}

		idInfo := getIdInfo(at)
		assert.Equal(t, "at-namespace", idInfo.Rest.Namespace)
	})
}

func TestAuthInfo_GetTokenPermissions(t *testing.T) {
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

func TestAuthInfo_GetSubject(t *testing.T) {
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

func TestAuthInfo_GetName(t *testing.T) {
	tests := []struct {
		name     string
		authInfo *AuthInfo
		expected string
	}{
		{
			name: "ID token is present, return ID token name",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
				},
				id: &Claims[IDTokenClaims]{
					Rest: IDTokenClaims{
						DisplayName: "id_name",
					},
					Claims: jwt.Claims{
						Subject: "id_subject",
					},
				},
			},
			expected: "id_name",
		},
		{
			name: "No ID token, actor is present, return actor subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
					Rest: AccessTokenClaims{
						Actor: &ActorClaims{
							Subject: "actor_subject",
						},
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
			result := tt.authInfo.GetName()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthInfo_GetUID(t *testing.T) {
	tests := []struct {
		name     string
		authInfo *AuthInfo
		expected string
	}{
		{
			name: "ID token is present, return ID token UID",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
				},
				id: &Claims[IDTokenClaims]{
					Rest: IDTokenClaims{
						Type:       "type",
						Identifier: "identifier",
					},
				},
			},
			expected: "type:identifier",
		},
		{
			name: "No ID token, actor is present, return actor subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
					Rest: AccessTokenClaims{
						Actor: &ActorClaims{
							Subject: "actor_subject",
						},
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
			result := tt.authInfo.GetUID()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthInfo_GetIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		authInfo *AuthInfo
		expected string
	}{
		{
			name: "ID token is present, return ID token identifier",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
				},
				id: &Claims[IDTokenClaims]{
					Rest: IDTokenClaims{
						Type:       "type",
						Identifier: "identifier",
					},
				},
			},
			expected: "identifier",
		},
		{
			name: "No ID token, actor is present, return actor identifier from subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
					Rest: AccessTokenClaims{
						Actor: &ActorClaims{
							Subject: "access-policy:identifier",
						},
					},
				},
				id: nil,
			},
			expected: "identifier",
		},
		{
			name: "No ID token, no actor, return access token identifier from subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "access-policy:identifier",
					},
					Rest: AccessTokenClaims{},
				},
				id: nil,
			},
			expected: "identifier",
		},
		{
			name: "No ID token, actor is nil, return access token identifier from subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "access-policy:identifier",
					},
					Rest: AccessTokenClaims{
						Actor: nil,
					},
				},
				id: nil,
			},
			expected: "identifier",
		},
		{
			name: "No ID token, nested actor level 2, return innermost actor identifier from subject",
			authInfo: &AuthInfo{
				at: Claims[AccessTokenClaims]{
					Claims: jwt.Claims{
						Subject: "at_subject",
					},
					Rest: AccessTokenClaims{
						Actor: &ActorClaims{
							Subject: "access-policy:identifier1",
							Actor: &ActorClaims{
								Subject: "access-policy:identifier2",
							},
						},
					},
				},
				id: nil,
			},
			expected: "identifier2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.authInfo.GetIdentifier()
			assert.Equal(t, tt.expected, result)
		})
	}
}
