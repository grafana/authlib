package authn

import (
	"testing"

	"github.com/grafana/authlib/types"
	"github.com/stretchr/testify/assert"
)

func TestAccessToken_getInnermostActor(t *testing.T) {
	t.Run("no actor", func(t *testing.T) {
		claims := AccessTokenClaims{}
		actor := claims.getInnermostActor()
		var nilActor *ActorClaims
		assert.Equal(t, nilActor, actor)
	})

	t.Run("root-level actor", func(t *testing.T) {
		claims := AccessTokenClaims{
			Actor: &ActorClaims{
				Subject: "subject",
			},
		}

		actor := claims.getInnermostActor()
		assert.Equal(t, "subject", actor.Subject)
	})

	t.Run("innermost actor", func(t *testing.T) {
		claims := AccessTokenClaims{
			Actor: &ActorClaims{
				Subject: "subject",
				Actor: &ActorClaims{
					Subject: "nested-subject",
					Actor: &ActorClaims{
						Subject: "innermost-subject",
					},
				},
			},
		}

		actor := claims.getInnermostActor()
		assert.Equal(t, "innermost-subject", actor.Subject)
	})
}

func TestAccessToken_GetIdentityActor(t *testing.T) {
	t.Run("no actor", func(t *testing.T) {
		claims := AccessTokenClaims{}
		actor := claims.GetIdentityActor()
		var nilActor *ActorClaims
		assert.Equal(t, nilActor, actor)
	})

	t.Run("non-identity actor", func(t *testing.T) {
		claims := AccessTokenClaims{
			Actor: &ActorClaims{
				IDTokenClaims: IDTokenClaims{
					Type: types.TypeAccessPolicy,
				},
			},
		}

		actor := claims.GetIdentityActor()
		var nilActor *ActorClaims
		assert.Equal(t, nilActor, actor)
	})

	t.Run("nested user actor", func(t *testing.T) {
		claims := AccessTokenClaims{
			Actor: &ActorClaims{
				Actor: &ActorClaims{
					Subject: "nested-user-actor",
					IDTokenClaims: IDTokenClaims{
						Type: types.TypeUser,
					},
				},
			},
		}

		actor := claims.GetIdentityActor()
		assert.Equal(t, "nested-user-actor", actor.Subject)
	})

	t.Run("nested service account actor", func(t *testing.T) {
		claims := AccessTokenClaims{
			Actor: &ActorClaims{
				Actor: &ActorClaims{
					Subject: "nested-user-actor",
					IDTokenClaims: IDTokenClaims{
						Type: types.TypeServiceAccount,
					},
				},
			},
		}

		actor := claims.GetIdentityActor()
		assert.Equal(t, "nested-user-actor", actor.Subject)
	})
}
