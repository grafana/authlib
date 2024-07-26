package authn

import (
	"context"
	"errors"
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

	type idKey struct{}

	// Decorate client with IDTokenExtractorOption
	WithIDTokenExtractorOption(func(ctx context.Context) (string, error) {
		idToken, ok := ctx.Value(idKey{}).(string)
		if !ok {
			return "", errors.New("id_token not found in context")
		}
		return idToken, nil
	})(gci)

	// Add id_token to context
	ctx := context.WithValue(context.Background(), idKey{}, "some-id-token")

	ctx, err := gci.wrapContext(ctx)
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

func TestGrpcClientInterceptor_wrapContextNoAccessToken(t *testing.T) {
	gci, err := NewGrpcClientInterceptor(&GrpcClientConfig{}, WithDisableAccessTokenOption())
	require.NoError(t, err)

	type idKey struct{}

	// Decorate client with IDTokenExtractorOption
	WithIDTokenExtractorOption(func(ctx context.Context) (string, error) {
		idToken, ok := ctx.Value(idKey{}).(string)
		if !ok {
			return "", errors.New("id_token not found in context")
		}
		return idToken, nil
	})(gci)

	// Add id_token to context
	ctx := context.WithValue(context.Background(), idKey{}, "some-id-token")

	ctx, err = gci.wrapContext(ctx)
	require.NoError(t, err)

	md, ok := metadata.FromOutgoingContext(ctx)
	require.True(t, ok)
	require.Len(t, md, 1)
	mdIdKey := md.Get(DefaultIdTokenMetadataKey)
	require.Len(t, mdIdKey, 1)
	idToken := mdIdKey[0]
	require.Equal(t, idToken, "some-id-token")
}
