package authn

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnsafeVerifier_Verify(t *testing.T) {
	type CustomClaims struct{}

	verifier := NewUnsafeVerifier[CustomClaims](
		VerifierConfig{},
		TokenTypeID,
	)

	t.Run("invalid: wrong token format", func(t *testing.T) {
		claims, err := verifier.Verify(context.Background(), "not a jwt token")
		assert.ErrorIs(t, err, ErrParseToken)
		assert.Nil(t, claims)
	})

	t.Run("invalid: token audience not allowed", func(t *testing.T) {
		verifier := NewUnsafeVerifier[CustomClaims](
			VerifierConfig{AllowedAudiences: []string{"stack:2"}},
			TokenTypeID,
		)
		claims, err := verifier.Verify(context.Background(), signFirst(t))
		assert.ErrorIs(t, err, ErrInvalidAudience)
		assert.Nil(t, claims)
	})

	t.Run("invalid: token expired", func(t *testing.T) {
		verifier := NewUnsafeVerifier[CustomClaims](
			VerifierConfig{},
			TokenTypeID,
		)
		claims, err := verifier.Verify(context.Background(), signExpired(t))
		assert.ErrorIs(t, err, ErrExpiredToken)
		assert.Nil(t, claims)
	})

	t.Run("invalid: wrong token typ", func(t *testing.T) {
		verifier := NewUnsafeVerifier[CustomClaims](
			VerifierConfig{},
			TokenTypeAccess,
		)
		claims, err := verifier.Verify(context.Background(), signFirst(t))
		assert.ErrorIs(t, err, ErrInvalidTokenType)
		assert.Nil(t, claims)
	})

	t.Run("valid: token audience allowed", func(t *testing.T) {
		verifier := NewUnsafeVerifier[CustomClaims](
			VerifierConfig{AllowedAudiences: []string{"stack:1"}},
			TokenTypeID,
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
