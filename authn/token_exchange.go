package authn

import (
	"context"
)

var _ TokenExchangeClient = &TokenExchangeClientImpl{}

type TokenExchangeClientImpl struct {
	client client
}

func NewTokenExchangeClient(cfg Config) (*TokenExchangeClientImpl, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}

	return &TokenExchangeClientImpl{client: client}, nil
}

func (s *TokenExchangeClientImpl) GetAccessToken(ctx context.Context, req AccessTokenRequest) (string, error) {
	return s.client.GetAccessToken(ctx, req)
}
