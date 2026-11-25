package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/authn"
)

func TestEnforcementClient_EmptyAudienceAllowlistRejectsForeignIDToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const kid = "audience-test-key"
	const audience = "other-service"

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	t.Cleanup(jwks.Close)

	var lookups atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"1":{"folders:read":["folders:uid:abc"]}}`))
	}))
	t.Cleanup(api.Close)

	token := signIDToken(t, key, kid, audience)

	// The same token is acceptable when a verifier is given this audience.
	// newClient hardcodes an empty allowlist, so enforcement must still refuse it
	// and must not call the permissions API.
	keys := authn.NewKeyRetriever(authn.KeyRetrieverConfig{SigningKeysURL: jwks.URL})
	verifier := authn.NewIDTokenVerifier(authn.VerifierConfig{
		AllowedAudiences: jwt.Audience{audience},
	}, keys)
	claims, err := verifier.Verify(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "user:1", claims.Subject)

	client, err := NewEnforcementClient(Config{
		APIURL:  api.URL,
		JWKsURL: jwks.URL,
		Token:   "placeholder-service-credential",
	})
	require.NoError(t, err)

	allowed, err := client.HasAccess(context.Background(), token, "folders:read")
	if err == nil {
		t.Fatalf("enforcement client accepted id token audience=%v subject=%s allowed=%v lookups=%d",
			claims.Audience, claims.Subject, allowed, lookups.Load())
	}
	require.False(t, allowed)
	require.Zero(t, lookups.Load(), "permissions lookup ran before the foreign-audience token was refused")
}

func signIDToken(t *testing.T, key *ecdsa.PrivateKey, kid, audience string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"kid": kid,
			"typ": authn.TokenTypeID,
		},
	})
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  "user:1",
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}).Serialize()
	require.NoError(t, err)
	return token
}
