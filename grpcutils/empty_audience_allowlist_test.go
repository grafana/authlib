package grpcutils

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
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/metadata"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/types"
)

func TestNewAuthenticator_EmptyAudienceAllowlistDoesNotAuthenticateForeignToken(t *testing.T) {
	key, kid, jwksURL := accessTokenJWKS(t)
	token := signForeignAccessToken(t, key, kid, "low-privilege-service", "stacks-1", []string{"folders:read"})
	tracer := noop.NewTracerProvider().Tracer("empty-audience")

	t.Run("zero allowlist", func(t *testing.T) {
		authenticate := NewAuthenticator(&AuthenticatorConfig{SigningKeysURL: jwksURL}, tracer)
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("X-Access-Token", token))

		out, err := authenticate(ctx)
		if err == nil {
			info, ok := types.AuthInfoFrom(out)
			require.True(t, ok)
			t.Fatalf("empty allowlist authenticated token audience=%v namespace=%s permissions=%v",
				info.GetAudience(), info.GetNamespace(), info.GetTokenPermissions())
		}
		requireNoAuthInfo(t, out)
	})

	t.Run("configured allowlist rejects a different audience", func(t *testing.T) {
		authenticate := NewAuthenticator(&AuthenticatorConfig{
			SigningKeysURL:   jwksURL,
			AllowedAudiences: []string{"this-service"},
		}, tracer)
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("X-Access-Token", token))

		out, err := authenticate(ctx)
		require.Error(t, err)
		requireNoAuthInfo(t, out)
	})

	t.Run("configured allowlist returns the permissions from the presented token", func(t *testing.T) {
		authenticate := NewAuthenticator(&AuthenticatorConfig{
			SigningKeysURL:   jwksURL,
			AllowedAudiences: []string{"this-service", "low-privilege-service"},
		}, tracer)
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("X-Access-Token", token))

		out, err := authenticate(ctx)
		require.NoError(t, err)
		info, ok := types.AuthInfoFrom(out)
		require.True(t, ok)
		require.Equal(t, []string{"low-privilege-service"}, info.GetAudience())
		require.Equal(t, "stacks-1", info.GetNamespace())
		require.Equal(t, []string{"folders:read"}, info.GetTokenPermissions())
	})
}

func TestNewUnsafeAuthenticator_EmptyAudienceAllowlistDoesNotAuthenticateForeignToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token := signForeignAccessToken(t, key, "audience-test-key", "low-privilege-service", "stacks-1", []string{"folders:read"})

	authenticate := NewUnsafeAuthenticator(noop.NewTracerProvider().Tracer("empty-audience"))
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("X-Access-Token", token))

	out, err := authenticate(ctx)
	if err == nil {
		info, ok := types.AuthInfoFrom(out)
		require.True(t, ok)
		t.Fatalf("unsafe authenticator with empty allowlist authenticated token audience=%v permissions=%v",
			info.GetAudience(), info.GetTokenPermissions())
	}
	requireNoAuthInfo(t, out)
}

func requireNoAuthInfo(t *testing.T, ctx context.Context) {
	t.Helper()
	if ctx == nil {
		return
	}
	info, ok := types.AuthInfoFrom(ctx)
	if ok && info != nil {
		t.Fatalf("auth info attached after rejection: audience=%v namespace=%s permissions=%v",
			info.GetAudience(), info.GetNamespace(), info.GetTokenPermissions())
	}
}

func accessTokenJWKS(t *testing.T) (*ecdsa.PrivateKey, string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const kid = "audience-test-key"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, err := json.Marshal(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       key.Public(),
				KeyID:     kid,
				Algorithm: string(jose.ES256),
			}},
		})
		require.NoError(t, err)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return key, kid, srv.URL
}

func signForeignAccessToken(t *testing.T, key *ecdsa.PrivateKey, kid, audience, namespace string, permissions []string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"kid": kid,
			"typ": authn.TokenTypeAccess,
		},
	})
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  "access-policy:foreign",
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}).Claims(authn.AccessTokenClaims{
		Namespace:   namespace,
		Permissions: permissions,
	}).Serialize()
	require.NoError(t, err)
	return token
}
