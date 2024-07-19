package authn

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

type FakeTokenExchanger struct {
	token string
}

func (f *FakeTokenExchanger) Exchange(ctx context.Context, req TokenExchangeRequest) (*TokenExchangeResponse, error) {
	return &TokenExchangeResponse{Token: f.token}, nil
}

func setupGrpcClientInterceptor(t *testing.T) (*GrpcClientInterceptor, *FakeTokenExchanger) {
	tokenClient := &FakeTokenExchanger{token: "some-token"}

	client, err := NewGrpcClientInterceptor(
		&GrpcClientConfig{TokenRequest: &TokenExchangeRequest{Namespace: "some-namespace", Audiences: []string{"some-service"}}},
		WithTokenClientOption(tokenClient),
	)
	require.NoError(t, err)

	return client, tokenClient
}

func TestGrpcClientInterceptor_wrapContext(t *testing.T) {
	gci, _ := setupGrpcClientInterceptor(t)

	// Decorate client with IDTokenExtractorOption
	WithIDTokenExtractorOption(func(ctx context.Context) (string, error) {
		return "some-id-token", nil
	})(gci)

	ctx, err := gci.wrapContext(context.Background())
	require.NoError(t, err)

	md, ok := metadata.FromOutgoingContext(ctx)
	require.True(t, ok)
	require.Len(t, md, 2)
	mdAtKey := md.Get(DefaultAccessTokenMetadataKey)
	require.Len(t, mdAtKey, 1)
	token := mdAtKey[0]
	require.Equal(t, token, "some-token")

	mdIdKey := md.Get(DefaultIdTokenMetadataKey)
	require.Len(t, mdIdKey, 1)
	idToken := mdIdKey[0]
	require.Equal(t, idToken, "some-id-token")
}
