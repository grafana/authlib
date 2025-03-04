# Authentication using GRPC

To perform authentication between two services using access and id tokens we need to setup a grpc compatible authenticator on for the server and have a way for the client to generate the access token.

### Example server side

For a grpc server we can leverage our generic [`Authenticator`](../authn/authenticator.go). To set it up we need to configure a [`KeyRetriever`](../authn/jwks.go) and setup [`AccessTokenVerifier`](../authn/verifier_access_token.go) and  
[`IDTokenVerifier`](../authn/verifier_id_token.go). The example setup below will extract id and access tokens from grpc metadata and validate that:
1. The signature is correct
2. The token contains the audience we configured it to check.
3. On success set [`AuthInfo`](../types/auth.go) in context that we can extract later using `types.AuthInfoFrom`.

```go
import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
)

func main() {
	// A grpc service
	service := MyService{}

	// Setup a key retriver. This is used to fetch and cache
	// public keys used to verify tokens.
	ks := authn.NewKeyRetriever(authn.KeyRetrieverConfig{
		SigningKeysURL: "url-to-fetch-public-keys-from",
	})

	// For remote communication, this authenticator ensures secure access by:
	//  1. Validating ID and access tokens against the signing server's keys.
	//  2. Verifying this service's identifier is present in the access token's
	//     audience list, confirming intended authorization.
	authenticator := authn.NewDefaultAuthenticator(
		authn.NewAccessTokenVerifier(authn.VerifierConfig{
			AllowedAudiences: []string{"required-audience"},
		}, ks),
		authn.NewIDTokenVerifier(authn.VerifierConfig{}, ks),
	)

	// Create a function that can be used by grpcAuth server interceptors.
	// On success this will set AuthInfo in context and types.AuthInfoFrom(ctx)
	// can be used to extract it.
	authfn := func(ctx context.Context) (context.Context, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, errors.New("missing metedata in context")
		}

		info, err := authenticator.Authenticate(ctx, authn.NewGRPCTokenProvider(md))
		if err != nil {
			if authn.IsUnauthenticatedErr(err) {
				return nil, status.Error(codes.Unauthenticated, err.Error())
			}

			return ctx, status.Error(codes.Internal, err.Error())
		}

		return types.WithAuthInfo(ctx, info), nil
	}

	// Create a new grpc server
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			auth.UnaryServerInterceptor(authfn),
		),
		grpc.ChainStreamInterceptor(
			auth.StreamServerInterceptor(authfn),
		),
	)
	server.RegisterService(&MyService_ServiceDesc, service)

	// ...
}
```

### Example client side

On client side we need to "exchange" our provisioned token for an access token for outgoing requests. We should also add id token to the request if we have it in context to propagate the identity of the original caller.
To do this we need to set up [`TokenExchanger`](../authn/token_exchange.go) and a [`GrpcClientInterceptor`](../authn/grpc_client_interceptor.go). 

```go
// idTokenExtractor is a helper function to get the user ID Token from context
func idTokenExtractor(ctx context.Context) (string, error) {
	info, ok := types.AuthInfoFrom(ctx)
	if !ok {
		return "", fmt.Errorf("no claims found")
	}

	if token := info.GetIDToken(); len(token) != 0 {
		return token, nil
	}

	return "", fmt.Errorf("id-token not found")
}

func main() {
	// A token exchanger is used to exhange a provisioned token against
	// a Access token.
	ts, err := authn.NewTokenExchangeClient(authn.TokenExchangeConfig{
		Token:            "my-token",
		TokenExchangeURL: "my-token-exhange-url",
	})
	if err != nil {
		panic(err)
	}

	// The client interceptor will add tokens to grpc metadata for all outgoing requests. It uses the provided
    // TokenExchanger to inject access tokens.
	clientInt := authn.NewGrpcClientInterceptor(
		ts,
		authn.WithClientInterceptorAudience([]string{"target-audience"}),
		authn.WithClientInterceptorNamespace("target-namespace"),
		authn.WithClientInterceptorIDTokenExtractor(idTokenExtractor),
	)

	// Setup grpc client connections with interceptors that can rotate and forward tokens.
	conn, err := grpc.NewClient(
		"myService:10000",
		grpc.WithUnaryInterceptor(clientInt.UnaryClientInterceptor),
		grpc.WithStreamInterceptor(clientInt.StreamClientInterceptor),
	)
}
```
