package idtoken

import (
	"context"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

type Verifier[T any] interface {
	Verify(ctx context.Context, token string) (*Claims[T], error)
}

type Claims[T any] struct {
	*jwt.Claims
	Rest T
}

func NewVerifier[T any](cfg Config) *VerifierBase[T] {
	return &VerifierBase[T]{cfg, newJWKSService(cfg.SigningKeyURL)}
}

type VerifierBase[T any] struct {
	cfg  Config
	keys *keyService
}

func (v *VerifierBase[T]) Verify(ctx context.Context, token string) (*Claims[T], error) {
	parsed, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, ErrPraseToken
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

	return &claims, nil
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
