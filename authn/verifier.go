package authn

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

type TokenType = string

const (
	TokenTypeID     TokenType = "jwt"
	TokenTypeAccess TokenType = "at+jwt"
)

type Claims[T any] struct {
	jwt.Claims
	Rest T

	// The original raw token
	token string `json:"-"`
}

func (c Claims[T]) MarshalJSON() ([]byte, error) {
	// Create a combined map with fields from both Claims and Rest
	combined := make(map[string]interface{})

	// Marshal jwt.Claims to get standard claims
	standardClaims, err := json.Marshal(c.Claims)
	if err != nil {
		return nil, err
	}

	// Marshal Rest to get custom claims
	restClaims, err := json.Marshal(c.Rest)
	if err != nil {
		return nil, err
	}

	// Unmarshal both into the combined map
	if err := json.Unmarshal(standardClaims, &combined); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(restClaims, &combined); err != nil {
		return nil, err
	}

	return json.Marshal(combined)
}

type Verifier[T any] interface {
	// Verify will parse and verify provided token, if `AllowedAudiences` was configured those will be validated as well.
	Verify(ctx context.Context, token string) (*Claims[T], error)
}

func NewVerifier[T any](cfg VerifierConfig, typ TokenType, keys KeyRetriever) *VerifierBase[T] {
	return &VerifierBase[T]{cfg, typ, keys}
}

type VerifierBase[T any] struct {
	cfg       VerifierConfig
	tokenType TokenType
	keys      KeyRetriever
}

// Verify will parse and verify provided token, if `AllowedAudiences` was configured those will be validated as well.
func (v *VerifierBase[T]) Verify(ctx context.Context, token string) (*Claims[T], error) {
	parsed, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, ErrParseToken
	}

	if !validType(parsed, v.tokenType) {
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

	claims := Claims[T]{
		token: token, // hold on to the original token
	}
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
	if typ == "" {
		return true
	}

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
