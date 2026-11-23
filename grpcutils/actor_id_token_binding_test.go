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
	"github.com/grafana/authlib/authz"
	"github.com/grafana/authlib/types"
)

func TestGRPCAuthenticatorBindsActorSubject(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const kid = "binding-test-key"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		payload, encErr := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     kid,
			Algorithm: string(jose.ES256),
		}}})
		require.NoError(t, encErr)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(server.Close)

	intercept := NewAuthenticator(&AuthenticatorConfig{
		SigningKeysURL:   server.URL,
		AllowedAudiences: []string{"resource-server"},
	}, noop.NewTracerProvider().Tracer("grpcutils.Authenticate"))

	sign := func(t *testing.T, typ, subject string, body any, audience []string) string {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]any{"kid": kid, "typ": typ},
		})
		require.NoError(t, err)
		token, err := jwt.Signed(signer).Claims(body).Claims(jwt.Claims{
			Subject:  subject,
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Audience: audience,
		}).Serialize()
		require.NoError(t, err)
		return token
	}

	accessFor := func(t *testing.T, namespace string, actor *authn.ActorClaims) string {
		t.Helper()
		return sign(t, authn.TokenTypeAccess, "access-policy:svc", authn.AccessTokenClaims{
			Namespace:            namespace,
			DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"},
			Permissions:          []string{"dashboards.grafana.app/dashboards:delete"},
			Actor:                actor,
		}, []string{"resource-server"})
	}
	userA := &authn.ActorClaims{
		Subject: "user:1",
		IDTokenClaims: authn.IDTokenClaims{
			Identifier: "1",
			Type:       types.TypeUser,
			Email:      "actor-a@example.com",
		},
	}
	idFor := func(t *testing.T, subject, identifier, namespace, email string) string {
		t.Helper()
		return sign(t, authn.TokenTypeID, subject, authn.IDTokenClaims{
			Identifier: identifier,
			Type:       types.TypeUser,
			Namespace:  namespace,
			Email:      email,
		}, nil)
	}

	call := func(t *testing.T, access, id string) (context.Context, error) {
		t.Helper()
		md := metadata.Pairs("X-Access-Token", access, "X-Id-Token", id)
		return intercept(metadata.NewIncomingContext(context.Background(), md))
	}

	reject := func(t *testing.T, out context.Context, err error) {
		t.Helper()
		if err == nil {
			info, ok := types.AuthInfoFrom(out)
			if !ok {
				t.Fatal("interceptor accepted the call and stored no identity")
			}
			decision := authz.CheckServicePermissions(info, "dashboards.grafana.app", "dashboards", "get")
			t.Fatalf("interceptor stored subject %q uid %q namespace %q delegated %v serviceCall %v allowed %v",
				info.GetSubject(), info.GetUID(), info.GetNamespace(), info.GetTokenDelegatedPermissions(), decision.ServiceCall, decision.Allowed)
		}
		if out != nil {
			_, ok := types.AuthInfoFrom(out)
			require.False(t, ok)
		}
	}

	t.Run("metadata for another user is rejected", func(t *testing.T) {
		out, err := call(t, accessFor(t, "stacks-1", userA), idFor(t, "user:2", "2", "stacks-1", "user-b@example.com"))
		reject(t, out, err)
	})

	t.Run("wildcard namespace metadata for another user is rejected", func(t *testing.T) {
		out, err := call(t, accessFor(t, "*", userA), idFor(t, "user:2", "2", "stacks-9", "user-b@example.com"))
		reject(t, out, err)
	})

	t.Run("matching metadata stays the bound user", func(t *testing.T) {
		out, err := call(t, accessFor(t, "stacks-1", userA), idFor(t, "user:1", "1", "stacks-1", "id-a@example.com"))
		require.NoError(t, err)
		info, ok := types.AuthInfoFrom(out)
		require.True(t, ok)
		require.Equal(t, "user:1", info.GetSubject())
		require.Equal(t, "user:1", info.GetUID())
		require.Equal(t, "id-a@example.com", info.GetEmail())
		require.Equal(t, []string{"dashboards.grafana.app/dashboards:get"}, info.GetTokenDelegatedPermissions())
		require.Empty(t, info.GetTokenPermissions())
		allowed := authz.CheckServicePermissions(info, "dashboards.grafana.app", "dashboards", "get")
		require.False(t, allowed.ServiceCall)
		require.True(t, allowed.Allowed)
		denied := authz.CheckServicePermissions(info, "dashboards.grafana.app", "dashboards", "delete")
		require.False(t, denied.Allowed)
	})

	t.Run("no identity actor still accepts the id token", func(t *testing.T) {
		out, err := call(t, accessFor(t, "stacks-1", nil), idFor(t, "user:2", "2", "stacks-1", "user-b@example.com"))
		require.NoError(t, err)
		info, ok := types.AuthInfoFrom(out)
		require.True(t, ok)
		require.Equal(t, "user:2", info.GetUID())
		decision := authz.CheckServicePermissions(info, "dashboards.grafana.app", "dashboards", "get")
		require.False(t, decision.ServiceCall)
		require.True(t, decision.Allowed)
	})
}
