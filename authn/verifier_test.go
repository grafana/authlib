package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var firstKeyID = "key-1"
var firstKey = decodePrivateKey([]byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEID6lXWsmcv/UWn9SptjOThsy88cifgGIBj2Lu0M9I8tQoAoGCCqGSM49
AwEHoUQDQgAEsf6eNnNMNhl+q7jXsbdUf3ADPh248uoFUSSV9oBzgptyokHCjJz6
n6PKDm2W7i3S2+dAs5M5f3s7d8KiLjGZdQ==
-----END EC PRIVATE KEY-----
`))

var secondKeyId = "key-2"
var secondKey = decodePrivateKey([]byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAu+avTG/oVGwVv1f52UBJ9afHZLnbfCxKowdDidrRPToAoGCCqGSM49
AwEHoUQDQgAEyg76i36+fP79FOQhsIhvAE4St9GJBjDm1119oaOtSzhQyx/tYZIi
ogn7UkIO0mXbES116mFI+YbC6wUpic3M2w==
-----END EC PRIVATE KEY-----
`))

func decodePrivateKey(data []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(data)
	if block == nil {
		panic("should include PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("should be able to parse ec private key: %v", err))

	}
	if privateKey.Curve.Params().Name != "P-256" {
		panic("should be valid private key")
	}

	return privateKey
}

func TestVerifier_Verify(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		response, err := json.Marshal(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: firstKey.Public(), KeyID: firstKeyID, Algorithm: string(jose.ES256)},
			},
		})
		require.NoError(t, err)
		_, _ = w.Write([]byte(response))
	}))

	type CustomClaims struct{}

	verifier := NewVerifier[CustomClaims](
		VerifierConfig{},
		TokenTypeID,
		NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: server.URL}),
	)

	t.Run("invalid: wrong token format", func(t *testing.T) {
		claims, err := verifier.Verify(context.Background(), "not a jwt token")
		assert.ErrorIs(t, err, ErrParseToken)
		assert.Nil(t, claims)
	})

	t.Run("invalid: unknown signing key", func(t *testing.T) {
		claims, err := verifier.Verify(context.Background(), signSecond(t))
		assert.ErrorIs(t, err, ErrInvalidSigningKey)
		assert.Nil(t, claims)
	})

	t.Run("invalid: transient http error", func(t *testing.T) {
		verifier := NewVerifier[CustomClaims](
			VerifierConfig{},
			TokenTypeID,
			NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: "http://localhost:8000/v1/unknown"}),
		)
		claims, err := verifier.Verify(context.Background(), signFirst(t))
		assert.ErrorIs(t, err, ErrFetchingSigningKey)
		assert.Nil(t, claims)
	})

	t.Run("invalid: unexpected status code", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		verifier := NewVerifier[CustomClaims](
			VerifierConfig{},
			TokenTypeID,
			NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: server.URL}),
		)
		claims, err := verifier.Verify(context.Background(), signFirst(t))
		assert.ErrorIs(t, err, ErrFetchingSigningKey)
		assert.Nil(t, claims)
	})

	t.Run("invalid: correct key id but wrong key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			response, err := json.Marshal(jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{Key: secondKey.Public(), KeyID: firstKeyID, Algorithm: string(jose.ES256)},
				},
			})
			require.NoError(t, err)
			_, _ = w.Write([]byte(response))
		}))

		verifier := NewVerifier[CustomClaims](
			VerifierConfig{},
			TokenTypeID,
			NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: server.URL}),
		)
		claims, err := verifier.Verify(context.Background(), signSecond(t))
		assert.ErrorIs(t, err, ErrInvalidSigningKey)
		assert.Nil(t, claims)
	})

	t.Run("invalid: token audience not allowed", func(t *testing.T) {
		verifier := NewVerifier[CustomClaims](
			VerifierConfig{AllowedAudiences: []string{"stack:2"}},
			TokenTypeID,
			NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: server.URL}),
		)
		claims, err := verifier.Verify(context.Background(), signFirst(t))
		assert.ErrorIs(t, err, ErrInvalidAudience)
		assert.Nil(t, claims)
	})

	t.Run("invalid: token expired", func(t *testing.T) {
		verifier := NewVerifier[CustomClaims](
			VerifierConfig{},
			TokenTypeID,
			NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: server.URL}),
		)
		claims, err := verifier.Verify(context.Background(), signExpired(t))
		assert.ErrorIs(t, err, ErrExpiredToken)
		assert.Nil(t, claims)
	})

	t.Run("invalid: wrong token typ", func(t *testing.T) {
		verifier := NewVerifier[CustomClaims](
			VerifierConfig{},
			TokenTypeAccess,
			NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: server.URL}),
		)
		claims, err := verifier.Verify(context.Background(), signFirst(t))
		assert.ErrorIs(t, err, ErrInvalidTokenType)
		assert.Nil(t, claims)
	})

	t.Run("valid: token audience allowed", func(t *testing.T) {
		verifier := NewVerifier[CustomClaims](
			VerifierConfig{AllowedAudiences: []string{"stack:1"}},
			TokenTypeID,
			NewKeyRetriever(KeyRetrieverConfig{SigningKeysURL: server.URL}),
		)
		claims, err := verifier.Verify(context.Background(), signFirst(t))
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})

	t.Run("valid: token", func(t *testing.T) {
		claims, err := verifier.Verify(context.Background(), signFirst(t))
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

func signExpired(t *testing.T) string {
	return signToken(t, firstKeyID, firstKey, time.Now().Add(-2*time.Minute))
}

func signFirst(t *testing.T) string {
	return signToken(t, firstKeyID, firstKey, time.Now().Add(1*time.Minute))
}

func signSecond(t *testing.T) string {
	return signToken(t, secondKeyId, secondKey, time.Now().Add(1*time.Minute))
}

func signToken(t *testing.T, keyID string, key *ecdsa.PrivateKey, exp time.Time) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": keyID,
			"typ": TokenTypeID,
		},
	})
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{Audience: jwt.Audience{"stack:1"}, Expiry: jwt.NewNumericDate(exp)}).Serialize()
	require.NoError(t, err)

	return token
}
