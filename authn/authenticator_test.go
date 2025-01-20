package authn

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/types"
)

func TestDefaultAuthenticator_Authenticate(t *testing.T) {
	authenticator := NewDefaultAuthenticator(
		NewUnsafeAccessTokenVerifier(VerifierConfig{}),
		NewUnsafeIDTokenVerifier(VerifierConfig{}),
	)

	t.Run("should allow request with only access token", func(t *testing.T) {
		provider := fakeTokenProvider{at: signAtToken(t, "access-policy:1", AccessTokenClaims{Namespace: "*"})}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.NoError(t, err)
		require.Equal(t, "access-policy:1", info.GetUID())
		require.Equal(t, "*", info.GetNamespace())
	})

	t.Run("should allow request with access and id token", func(t *testing.T) {
		provider := fakeTokenProvider{
			at: signAtToken(t, "access-policy:1", AccessTokenClaims{Namespace: "*"}),
			id: signIDToken(t, "user:1", IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "stacks-1",
			}),
		}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.NoError(t, err)
		require.Equal(t, "user:1", info.GetUID())
		require.Equal(t, "stacks-1", info.GetNamespace())
	})

	t.Run("should reject request if namespace don't match", func(t *testing.T) {
		provider := fakeTokenProvider{
			at: signAtToken(t, "access-policy:1", AccessTokenClaims{Namespace: "stacks-2"}),
			id: signIDToken(t, "user:1", IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "stacks-1",
			}),
		}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.Error(t, err)
		require.Nil(t, info)
	})

	t.Run("should reject request if only id token is provided", func(t *testing.T) {
		provider := fakeTokenProvider{
			id: signIDToken(t, "user:1", IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "stacks-1",
			}),
		}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.Error(t, err)
		require.Nil(t, info)
	})
}

func TestAccessTokenAuthenticator_Authenticate(t *testing.T) {
	authenticator := NewAccessTokenAuthenticator(
		NewUnsafeAccessTokenVerifier(VerifierConfig{}),
	)

	t.Run("should allow request with only access token", func(t *testing.T) {
		provider := fakeTokenProvider{at: signAtToken(t, "access-policy:1", AccessTokenClaims{Namespace: "*"})}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.NoError(t, err)
		require.Equal(t, "access-policy:1", info.GetUID())
		require.Equal(t, "*", info.GetNamespace())
	})

	t.Run("should ignore id token", func(t *testing.T) {
		provider := fakeTokenProvider{
			at: signAtToken(t, "access-policy:1", AccessTokenClaims{Namespace: "*"}),
			id: signIDToken(t, "user:1", IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "stacks-1",
			}),
		}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.NoError(t, err)
		require.Equal(t, "access-policy:1", info.GetUID())
		require.Equal(t, "*", info.GetNamespace())
	})

	t.Run("should reject request if no access token is provided", func(t *testing.T) {
		provider := fakeTokenProvider{
			id: signIDToken(t, "user:1", IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "stacks-1",
			}),
		}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.Error(t, err)
		require.Nil(t, info)
	})
}

func TestIDTokenAuthenticator_Authenticate(t *testing.T) {
	authenticator := NewIDTokenAuthenticator(
		NewUnsafeIDTokenVerifier(VerifierConfig{}),
	)

	t.Run("should allow request with id token", func(t *testing.T) {
		provider := fakeTokenProvider{
			id: signIDToken(t, "user:1", IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "stacks-1",
			}),
		}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.NoError(t, err)
		require.Equal(t, "user:1", info.GetUID())
		require.Equal(t, "stacks-1", info.GetNamespace())
	})

	t.Run("should ignore access token", func(t *testing.T) {
		provider := fakeTokenProvider{
			at: signAtToken(t, "access-policy:1", AccessTokenClaims{Namespace: "*"}),
			id: signIDToken(t, "user:1", IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "stacks-1",
			}),
		}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.NoError(t, err)
		require.Equal(t, "user:1", info.GetUID())
		require.Equal(t, "stacks-1", info.GetNamespace())
	})

	t.Run("should reject request if no id token is provided", func(t *testing.T) {
		provider := fakeTokenProvider{
			at: signAtToken(t, "access-policy:1", AccessTokenClaims{Namespace: "*"}),
		}

		info, err := authenticator.Authenticate(context.Background(), provider)
		require.Error(t, err)
		require.Nil(t, info)
	})
}

var _ TokenProvider = (*fakeTokenProvider)(nil)

type fakeTokenProvider struct {
	id string
	at string
}

func (f fakeTokenProvider) AccessToken(ctx context.Context) (string, bool) {
	return f.at, len(f.at) > 0
}

func (f fakeTokenProvider) IDToken(ctx context.Context) (string, bool) {
	return f.id, len(f.id) > 0
}

func signAtToken(t *testing.T, subject string, claims AccessTokenClaims) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte("key"),
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"typ": TokenTypeAccess,
		},
	})
	require.NoError(t, err)

	token, err := jwt.Signed(signer).
		Claims(&claims).
		Claims(&jwt.Claims{Subject: subject}).
		CompactSerialize()
	require.NoError(t, err)

	return token
}

func signIDToken(t *testing.T, subject string, claims IDTokenClaims) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte("key"),
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"typ": TokenTypeID,
		},
	})
	require.NoError(t, err)

	token, err := jwt.Signed(signer).
		Claims(&claims).
		Claims(&jwt.Claims{Subject: subject}).
		CompactSerialize()
	require.NoError(t, err)

	return token

}
