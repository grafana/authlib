package idtoken

import (
	"errors"
	"fmt"
)

var (
	ErrFetchingSigningKey = errors.New("unable to fetch signing keys")

	// Privite error we wrap all other exported errors with
	errInvalidToken      = errors.New("invalid token")
	ErrPraseToken        = fmt.Errorf("%w: failed to parse as jwt token", errInvalidToken)
	ErrInvalidSigningKey = fmt.Errorf("%w: unrecognized signing key", errInvalidToken)
	ErrInvalidAudience   = fmt.Errorf("%w: invalid audience", errInvalidToken)
)

func IsInvalidTokenErr(err error) bool {
	return errors.Is(err, errInvalidToken)
}
