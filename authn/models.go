package authn

import (
	"context"

	"github.com/go-jose/go-jose/v3/jwt"
)

// client performs requests to auth server
type client interface {
	// GetAccessToken returns a short-lived access Token for the given claims.
	GetAccessToken(ctx context.Context, req AccessTokenRequest) (string, error)
}

type TokenExchangeClient interface {
	// GetAccessToken returns a short-lived access Token for the given claims.
	GetAccessToken(ctx context.Context, req AccessTokenRequest) (string, error)
}

type Config struct {
	CAP        string `json:"cloudAccessPolicy"` // cloud access policy token used for authorising the request
	AuthAPIURL string `json:"authAPIURL"`        // URL of the auth server
}

type AccessTokenRequest struct {
	Claims jwt.Claims     `json:"claims"` // claims to be included in the access token
	Extra  map[string]any `json:"extra"`
}

type Data struct {
	Token string `json:"token"`
}

type tokenExchangeResponse struct {
	Data   Data   `json:"data"`
	Status string `json:"status"`
	Error  string `json:"error"`
}
