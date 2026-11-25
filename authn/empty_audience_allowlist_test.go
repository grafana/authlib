package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

const (
	foreignAudience = "low-privilege-service"
	localAudience   = "this-service"
	foreignPerm     = "folders:read"
	foreignNS       = "stacks-1"
)

// signingFixture holds an ephemeral P-256 key and a JWKS endpoint that publishes it.
// The private key exists only in process memory.
type signingFixture struct {
	t   *testing.T
	kid string
	key *ecdsa.PrivateKey
	srv *httptest.Server
}

func newSigningFixture(t *testing.T) *signingFixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	f := &signingFixture{t: t, kid: "audience-test-key", key: key}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       key.Public(),
				KeyID:     f.kid,
				Algorithm: string(jose.ES256),
			}},
		})
		require.NoError(t, err)
		_, _ = w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *signingFixture) retriever() KeyRetriever {
	return NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: f.srv.URL})
}

func (f *signingFixture) sign(typ TokenType, audience string, access AccessTokenClaims) string {
	f.t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       f.key,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"kid": f.kid,
			"typ": typ,
		},
	})
	require.NoError(f.t, err)

	subject := "access-policy:foreign"
	if typ == TokenTypeID {
		subject = "user:1"
	}

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  subject,
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}).Claims(access).Serialize()
	require.NoError(f.t, err)
	return token
}

func foreignAccessClaims() AccessTokenClaims {
	return AccessTokenClaims{
		Namespace:   foreignNS,
		Permissions: []string{foreignPerm},
	}
}

func TestAccessTokenVerifier_EmptyAudienceAllowlistRejectsForeignToken(t *testing.T) {
	f := newSigningFixture(t)
	token := f.sign(TokenTypeAccess, foreignAudience, foreignAccessClaims())
	keys := f.retriever()

	t.Run("nil allowlist", func(t *testing.T) {
		assertForeignAccessTokenRejected(t, NewAccessTokenVerifier(VerifierConfig{}, keys), token)
	})

	t.Run("empty allowlist", func(t *testing.T) {
		assertForeignAccessTokenRejected(t, NewAccessTokenVerifier(VerifierConfig{
			AllowedAudiences: jwt.Audience{},
		}, keys), token)
	})

	t.Run("configured allowlist rejects a different audience", func(t *testing.T) {
		verifier := NewAccessTokenVerifier(VerifierConfig{
			AllowedAudiences: jwt.Audience{localAudience},
		}, keys)
		claims, err := verifier.Verify(context.Background(), token)
		require.ErrorIs(t, err, ErrInvalidAudience)
		require.Nil(t, claims)
	})

	t.Run("configured allowlist accepts its own audience and returns that token's permissions", func(t *testing.T) {
		verifier := NewAccessTokenVerifier(VerifierConfig{
			AllowedAudiences: jwt.Audience{localAudience, foreignAudience},
		}, keys)
		claims, err := verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		require.Equal(t, jwt.Audience{foreignAudience}, claims.Audience)
		require.Equal(t, []string{foreignPerm}, claims.Rest.Permissions)
		require.Equal(t, foreignNS, claims.Rest.Namespace)
	})

	t.Run("signature is still required when the allowlist is empty", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]any{"kid": f.kid, "typ": TokenTypeAccess},
		})
		require.NoError(t, err)
		forged, err := jwt.Signed(signer).Claims(jwt.Claims{
			Audience: jwt.Audience{foreignAudience},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		}).Claims(foreignAccessClaims()).Serialize()
		require.NoError(t, err)

		verifier := NewAccessTokenVerifier(VerifierConfig{}, keys)
		claims, err := verifier.Verify(context.Background(), forged)
		require.Error(t, err)
		require.Nil(t, claims)
	})
}

func TestUnsafeAccessTokenVerifier_EmptyAudienceAllowlistRejectsForeignToken(t *testing.T) {
	f := newSigningFixture(t)
	token := f.sign(TokenTypeAccess, foreignAudience, foreignAccessClaims())

	t.Run("nil allowlist", func(t *testing.T) {
		assertForeignAccessTokenRejected(t, NewUnsafeAccessTokenVerifier(VerifierConfig{}), token)
	})

	t.Run("explicit audience still verifies the same token", func(t *testing.T) {
		verifier := NewUnsafeAccessTokenVerifier(VerifierConfig{
			AllowedAudiences: jwt.Audience{foreignAudience},
		})
		claims, err := verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		require.Equal(t, []string{foreignPerm}, claims.Rest.Permissions)
	})
}

func TestIDTokenVerifier_EmptyAudienceAllowlistRejectsForeignToken(t *testing.T) {
	f := newSigningFixture(t)
	token := f.sign(TokenTypeID, foreignAudience, AccessTokenClaims{})
	keys := f.retriever()

	t.Run("nil allowlist", func(t *testing.T) {
		verifier := NewIDTokenVerifier(VerifierConfig{}, keys)
		claims, err := verifier.Verify(context.Background(), token)
		require.Error(t, err)
		require.Nil(t, claims)
	})

	t.Run("configured audience accepts the same token", func(t *testing.T) {
		verifier := NewIDTokenVerifier(VerifierConfig{AllowedAudiences: jwt.Audience{foreignAudience}}, keys)
		claims, err := verifier.Verify(context.Background(), token)
		require.NoError(t, err)
		require.Equal(t, jwt.Audience{foreignAudience}, claims.Audience)
		require.Equal(t, "user:1", claims.Subject)
	})
}

func TestUnsafeIDTokenVerifier_EmptyAudienceAllowlistRejectsForeignToken(t *testing.T) {
	f := newSigningFixture(t)
	token := f.sign(TokenTypeID, foreignAudience, AccessTokenClaims{})

	verifier := NewUnsafeIDTokenVerifier(VerifierConfig{})
	claims, err := verifier.Verify(context.Background(), token)
	require.Error(t, err)
	require.Nil(t, claims)
}

func TestDefaultAuthenticator_EmptyAudienceAllowlistDoesNotReturnForeignPermissions(t *testing.T) {
	f := newSigningFixture(t)
	token := f.sign(TokenTypeAccess, foreignAudience, foreignAccessClaims())
	keys := f.retriever()

	t.Run("header with bearer prefix and zero allowlist", func(t *testing.T) {
		auth := NewDefaultAuthenticator(
			NewAccessTokenVerifier(VerifierConfig{}, keys),
			NewIDTokenVerifier(VerifierConfig{AllowedAudiences: jwt.Audience{localAudience}}, keys),
		)
		req := httptest.NewRequest(http.MethodPost, "http://this-service.example/apis", nil)
		req.Header.Set(httpHeaderAccessToken, "Bearer "+token)

		info, err := auth.Authenticate(context.Background(), NewHTTPTokenProvider(req))
		if err == nil {
			t.Fatalf("empty allowlist accepted access token audience=%v namespace=%s permissions=%v",
				info.GetAudience(), info.GetNamespace(), info.GetTokenPermissions())
		}
		require.Nil(t, info)
	})

	t.Run("matching allowlist returns the permissions from that token", func(t *testing.T) {
		auth := NewDefaultAuthenticator(
			NewAccessTokenVerifier(VerifierConfig{AllowedAudiences: jwt.Audience{foreignAudience}}, keys),
			NewIDTokenVerifier(VerifierConfig{AllowedAudiences: jwt.Audience{localAudience}}, keys),
		)
		req := httptest.NewRequest(http.MethodPost, "http://this-service.example/apis", nil)
		req.Header.Set(httpHeaderAccessToken, "Bearer "+token)

		info, err := auth.Authenticate(context.Background(), NewHTTPTokenProvider(req))
		require.NoError(t, err)
		require.Equal(t, []string{foreignAudience}, info.GetAudience())
		require.Equal(t, foreignNS, info.GetNamespace())
		require.Equal(t, []string{foreignPerm}, info.GetTokenPermissions())
	})
}

func TestAccessTokenAuthenticator_EmptyAudienceAllowlistDoesNotReturnForeignPermissions(t *testing.T) {
	f := newSigningFixture(t)
	token := f.sign(TokenTypeAccess, foreignAudience, foreignAccessClaims())
	keys := f.retriever()

	auth := NewAccessTokenAuthenticator(NewAccessTokenVerifier(VerifierConfig{}, keys))
	req := httptest.NewRequest(http.MethodGet, "http://this-service.example/secret", nil)
	req.Header.Set(httpHeaderAccessToken, token)

	info, err := auth.Authenticate(context.Background(), NewHTTPTokenProvider(req))
	if err == nil {
		t.Fatalf("empty allowlist accepted access token audience=%v namespace=%s permissions=%v",
			info.GetAudience(), info.GetNamespace(), info.GetTokenPermissions())
	}
	require.Nil(t, info)
}

func assertForeignAccessTokenRejected(t *testing.T, verifier interface {
	Verify(ctx context.Context, token string) (*Claims[AccessTokenClaims], error)
}, token string) {
	t.Helper()

	claims, err := verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatalf("empty audience allowlist accepted token for audience %v namespace %s permissions %v",
			claims.Audience, claims.Rest.Namespace, claims.Rest.Permissions)
	}
	require.Nil(t, claims)
}
