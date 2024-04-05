package authn

import (
	"context"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

const (
	TypeIDToken     = "jwt"
	TypeAccessToken = "at+jwt"
)

type Verifier[T any] interface {
	// Verify will parse and verify provided token using public key from `IDVerifierConfig.SigningKeysURL`.
	// typ will either be `TypeIDToken` or `TypeAccessToken` depending on expected token to verify.
	// If `AllowedAudiences` was configured those will be validated as well.
	Verify(ctx context.Context, token, typ string) (*Claims[T], error)
}

type Claims[T any] struct {
	*jwt.Claims
	Rest T
}

func NewVerifier[T any](cfg IDVerifierConfig) *VerifierBase[T] {
	return newVerifierWithKeyService[T](cfg, newKeyService(cfg.SigningKeysURL))
}

func newVerifierWithKeyService[T any](cfg IDVerifierConfig, keys *keyService) *VerifierBase[T] {
	return &VerifierBase[T]{cfg, keys}
}

type VerifierBase[T any] struct {
	cfg  IDVerifierConfig
	keys *keyService
}

// Verify will parse and verify provided token using public key from `SigningKeysURL`.
// If `AllowedAutiences` was configured those will be validated as well.
func (v *VerifierBase[T]) Verify(ctx context.Context, token, typ string) (*Claims[T], error) {
	parsed, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, ErrParseToken
	}

	if !validType(parsed, typ) {
		return nil, ErrInvalidTokenType
	}

	keyID, err := getKeyID(parsed.Headers)
	if err != nil {
		return nil, err
	}

	jwk, err := v.keys.Get(ctx, keyID)
	if err != nil {
		return nil, err
	}

	claims := Claims[T]{}
	if err := parsed.Claims(jwk, &claims.Claims, &claims.Rest); err != nil {
		return nil, err
	}

	if err := claims.Validate(jwt.Expected{
		Audience: v.cfg.AllowedAudiences,
		Time:     time.Now(),
	}); err != nil {
		return nil, mapErr(err)
	}

	return &claims, nil
}

func validType(token *jwt.JSONWebToken, typ string) bool {
	for _, h := range token.Headers {
		if t, ok := h.ExtraHeaders["typ"].(string); ok && t == typ {
			return true
		}
	}
	return false
}

func mapErr(err error) error {
	if errors.Is(err, jwt.ErrExpired) {
		return ErrExpiredToken
	}

	if errors.Is(err, jwt.ErrInvalidAudience) {
		return ErrInvalidAudience
	}

	return err
}

func getKeyID(headers []jose.Header) (string, error) {
	for _, h := range headers {
		if h.KeyID != "" {
			return h.KeyID, nil
		}
	}
	return "", ErrInvalidSigningKey
}

func NewNoopVerifier[T any]() *NoopVerifier[T] {
	return &NoopVerifier[T]{}
}

type NoopVerifier[T any] struct{}

func (v *NoopVerifier[T]) Verify(ctx context.Context, token string) (*Claims[T], error) {
	return nil, nil
}
