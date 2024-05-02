package authn

import (
	"errors"
	"fmt"
)

var (
	ErrFetchingSigningKey = errors.New("unable to fetch signing keys")

	// Private error we wrap all other exported errors with
	errInvalidToken      = errors.New("invalid token")
	ErrParseToken        = fmt.Errorf("%w: failed to parse as jwt token", errInvalidToken)
	ErrInvalidTokenType  = fmt.Errorf("%w: invalid token type", errInvalidToken)
	ErrInvalidSigningKey = fmt.Errorf("%w: unrecognized signing key", errInvalidToken)

	ErrExpiredToken    = fmt.Errorf("%w: expired token", errInvalidToken)
	ErrInvalidAudience = fmt.Errorf("%w: invalid audience", errInvalidToken)
)

func IsInvalidTokenErr(err error) bool {
	return errors.Is(err, errInvalidToken)
}

var (
	ErrMissingNamespace = errors.New("missing required namespace")
	ErrInvalidNamespace = errors.New("invalid namespace specified during exchange")

	ErrMissingAudiences = errors.New("missing required audiences")

	ErrInvalidExchangeResponse = errors.New("invalid exchange response")
)
