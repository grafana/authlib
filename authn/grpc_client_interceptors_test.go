package authn

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestGrpcClientInterceptor_wrapContext(t *testing.T) {
	type idKey struct{}

	interceptor := NewGrpcClientInterceptor(
		NewStaticTokenExchanger("some-token"),
		WithClientInterceptorNamespace("some-namespace"),
		WithClientInterceptorAudience([]string{"some-service"}),
		WithClientInterceptorIDTokenExtractor(func(ctx context.Context) (string, error) {
			idToken, ok := ctx.Value(idKey{}).(string)
			if !ok {
				return "", errors.New("id_token not found in context")
			}
			return idToken, nil

		}),
	)

	// Setup existing outgoing headers
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		"x-header-one", "one",
		"x-header-ab", "aaa",
		"x-header-ab", "bbb",
	)

	// Add ID token to context
	ctx = context.WithValue(ctx, idKey{}, "some-id-token")

	ctx, err := interceptor.wrapContext(ctx)
	require.NoError(t, err)

	md, ok := metadata.FromOutgoingContext(ctx)
	require.True(t, ok)
	require.Len(t, md, 4)
	mdAtKey := md.Get(metadataKeyAccessToken)
	require.Len(t, mdAtKey, 1)
	token := mdAtKey[0]
	require.Equal(t, token, "some-token")

	mdIdKey := md.Get(metadataKeyIDTokenMetadata)
	require.Len(t, mdIdKey, 1)
	idToken := mdIdKey[0]
	require.Equal(t, idToken, "some-id-token")

	// The existing headers
	require.Equal(t, []string{"one"}, md.Get("x-header-one"))
	require.Equal(t, []string{"aaa", "bbb"}, md.Get("x-header-ab"))
}
