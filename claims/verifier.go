package claims

import "context"

type Verifier[T any] interface {
	// Verify will parse and verify provided token, if `AllowedAudiences` was configured those will be validated as well.
	// Additional claims will be
	VerifyToken(ctx context.Context, token string) (TokenClaims, T, error)
}
