# Authn: Robust JWT Verification for the Grafana Ecosystem

This library provides a robust and flexible way to verify JSON Web Tokens (JWTs) within the Grafana ecosystem.

**Features**:

- Generic JWT verifier with support for custom claims
- Specialized verifiers for Grafana ID Tokens and Access Tokens
- Composable gRPC interceptors for retrieving, sending then verifying tokens in request metadata

## Token verifier

This package will handle retrival and caching of jwks. It was desing to be generic over "Custom claims" so that we are not only restricted to the current structure of id tokens. This means that the parsed claims will contain standard jwts claims such as `aud`, `exp` etc plus specified custom claims.

```go
package main

import (
	"context"
	"log"

	"github.com/grafana/authlib/authn"
)

type CustomClaims struct{}

func main() {
	verifier := authn.NewVerifier[CustomClaims](authn.VerifierConfig{
		AllowedAudiences: []string{},
	}, authn.TokenTypeID, authn.NewKeyRetiever(KeyRetrieverConfig{SigningKeysURL: "<jwks url>"}))

	claims, err := verifier.Verify(context.Background(), "<token>")

	if err != nil {
		log.Fatal("failed to verify id token: ", err)
	}

	log.Println("Claims: ", claims)
}
```

The verifier is generic over jwt.Claims. Most common use cases will be to either verify Grafana issued ID-Token or Access token.
For those we have `AccessTokenVerifier` and `IDTokenVerifier`. These two structures are just simple wrappers around `Verifier` with expected claims.

## gRPC interceptors

This package simplifies the implementation of authentication within your gRPC services operating within the Grafana ecosystem.

**Key Components:**

- **Client-Side Interceptor**: Request access tokens from the Token Signing Server and enrich your gRPC requests with necessary metadata. This modular interceptor allows you to customize the added metadata based on your specific service requirements (e.g: user ID token, requested namespace).
- **Server-Side Authenticator**: Easily verify the validity of access tokens (and optionally ID tokens) against the Token Signing Server's public keys. This authenticator integrates directly with the standard grpc-ecosystem/go-grpc-middleware/auth interceptor for straightforward implementation.

### Example 1: Full authentication example with ID and Access Tokens

In this first example:

- We configure the client interceptor to interact with the `MyService` gRPC service. This interceptor uses its own `myClientToken` to request an access token from the token signing service at "/v1/sign-access-token". The requested access token will grant access to the `MyService` for the `stacks-22` namespace. The interceptor will also add the incoming user's ID token to the metadata, along with the query namespace using the `X-Namespace` key. We assume that `MyService` requires this additional Namespace metadata to determine which tenant is being queried.
- On the server side, we set up the interceptor for the `MyService` service. This interceptor extracts the access and ID tokens from the gRPC metadata. It then populates the application context with an `AuthInfo` object. Functions within `MyService` can use this `AuthInfo` object to access information about the caller (such as their permissions).

**Diagram:**

![full authentication flow](../assets/full-authentication-example.png)

**Client side:**

```go
import (
	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	"github.com/grafana/authlib/claims"
	"google.golang.org/grpc"
)

// idTokenExtractor is a helper function to get the user ID Token from context
func idTokenExtractor(ctx context.Context) (string, error) {
	authInfo, ok := claims.From(ctx)
	if !ok {
		return "", fmt.Errorf("no claims found")
	}

	extra := authInfo.GetExtra()
	if token, exists := extra["id-token"]; exists && len(token) != 0 && token[0] != "" {
		return token[0], nil
	}

	return "", fmt.Errorf("id-token not found")
}

// namespaceExtractor is a helper function used to populate gRPC metadata with the namespace
func namespaceExtractor(ctx context.Context) (key string, values []string, err error) {
	return authzlib.DefaultNamespaceMetadataKey, []string{"stacks-22"}, nil
}

func main() {
	// The client interceptor authenticates requests to the gRPC server using
	// the provided TokenExchangeConfig. It automatically handles token exchange
	// and injects the ID token along with the extracted StackID into the request metadata.
	clientInt, err := authnlib.NewGrpcClientInterceptor(
		&authnlib.GrpcClientConfig{
			TokenClientConfig: &authnlib.TokenExchangeConfig{
				Token:            "myClientToken",
				TokenExchangeURL: "https://token-signer/v1/sign-access-token",
			},
			TokenRequest: &authnlib.TokenExchangeRequest{
				Namespace: "stacks-22",
				Audiences: []string{"MyService"},
			},
		},
		authnlib.WithIDTokenExtractorOption(idTokenExtractor),
		authnlib.WithMetadataExtractorOption(namespaceExtractor),
	)
	if err != nil {
		os.Exit(1)
	}

	conn, err := grpc.NewClient(
		"myService:10000",
		grpc.WithUnaryInterceptor(clientInt.UnaryClientInterceptor),
		grpc.WithStreamInterceptor(clientInt.StreamClientInterceptor),
	)

	// ...
}
```

**Server side:**

```go
import (
	authnlib "github.com/grafana/authlib/authn"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"google.golang.org/grpc"
)

func main() (*authnlib.GrpcAuthenticator, error) {
	// A grpc service
	service := MyService{}

	// For remote communication, this authenticator ensures secure access by:
	//  1. Validating ID and access tokens against the signing server's keys.
	//  2. Verifying this service's identifier is present in the access token's
	//     audience list, confirming intended authorization.
	authenticator := authnlib.NewGrpcAuthenticator(
		&authnlib.GrpcAuthenticatorConfig{
			KeyRetrieverConfig: authnlib.KeyRetrieverConfig{
				SigningKeysURL: "https://token-signer/v1/keys",
			},
			VerifierConfig: authnlib.VerifierConfig{
				AllowedAudiences: []string{"MyService"},
			},
		},
		authnlib.WithIDTokenAuthOption(true),
	)

	// Create a new grpc server
	server = grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			auth.UnaryServerInterceptor(authenticator.Authenticate),
		),
		grpc.ChainStreamInterceptor(
			auth.StreamServerInterceptor(authenticator.Authenticate),
		),
	)
	server.RegisterService(&authzv1.MyService_ServiceDesc, service)

	// ...
}
```

### Example 2: Custom authentication flow with ID Token only and a custom metadata

In this second example:

- We configure the client interceptor to interact with the `MyService` gRPC service. This interceptor does not request an access token to interact with the `MyService` service but still adds the incoming user's ID token to the metadata, along with the `origin` using the `X-Origin` key. We assume that `MyService` requires this additional `origin` metadata to determine where the call is coming from and enforce some additional rules.
- On the server side, we set up the interceptor for the `MyService` service. This interceptor solely extracts the ID tokens from the gRPC metadata. It then populates the application context with an `AuthInfo` object. Functions within `MyService` can use this `AuthInfo` object to access information about the user.

**Diagram:**

![custom authentication flow](../assets/custom-authentication-example.png)

**Client side:**

```go
import (
	context
	errors

	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	"github.com/grafana/authlib/claims"
	"google.golang.org/grpc"
)

// In this example, OriginContextKey is the key used to store the origin in the context.
type OriginContextKey struct{}

// idTokenExtractor is a helper function to get the user ID Token from context
func idTokenExtractor(ctx context.Context) (string, error) {
	authInfo, ok := claims.From(ctx)
	if !ok {
		return "", fmt.Errorf("no claims found")
	}

	extra := authInfo.GetExtra()
	if token, exists := extra["id-token"]; exists && len(token) != 0 && token[0] != "" {
		return token[0], nil
	}

	return "", fmt.Errorf("id-token not found")
}

// originExtractor is a helper function populate gRPC metadata with a custom Origin metadata
func originExtractor(ctx context.Context) (key string, values []string, err error) {
	origin, ok := ctx.Value(OriginContextKey{}).(string)
	if !ok {
		return "", nil, errors.New("Missing origin from context")
	}
	return "X-Origin", []string{origin}, nil
}

func main() {
	// The client interceptor authenticates requests to the gRPC server injecting
	// the ID token along with a custom origin metadata into the request metadata.
	// Since we explicitly disable it, the client interceptor won't add a service
	// access token to the request.
	clientInt, err := authnlib.NewGrpcClientInterceptor(
		&authnlib.GrpcClientConfig{},
		authnlib.WithDisableAccessTokenOption(),
		authnlib.WithIDTokenExtractorOption(idTokenExtractor),
		authnlib.WithMetadataExtractorOption(originExtractor),
	)
	if err != nil {
		os.Exit(1)
	}

	conn, err := grpc.NewClient(
		"myService:10000",
		grpc.WithUnaryInterceptor(clientInt.UnaryClientInterceptor),
		grpc.WithStreamInterceptor(clientInt.StreamClientInterceptor),
	)

	// ...
}
```

**Server side:**

```go
import (
	authnlib "github.com/grafana/authlib/authn"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"google.golang.org/grpc"
)

func main() (*authnlib.GrpcAuthenticator, error) {
	// A grpc service
	service := MyService{}

	// This authenticator only verifies the ID token is present
	// and properly signed by the signing authority.
	authenticator := authnlib.NewGrpcAuthenticator(
		&authnlib.GrpcAuthenticatorConfig{
			KeyRetrieverConfig: authnlib.KeyRetrieverConfig{
				SigningKeysURL: "https://token-signer/v1/keys",
			},
			VerifierConfig: authnlib.VerifierConfig{},
		},
		authnlib.WithDisableAccessTokenAuthOption(),
		authnlib.WithIDTokenAuthOption(true),
	)

	// Create a new grpc server
	server = grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			auth.UnaryServerInterceptor(authenticator.Authenticate),
			// TODO - Add origin handler
		),
		grpc.ChainStreamInterceptor(
			auth.StreamServerInterceptor(authenticator.Authenticate),
			// TODO - Add origin handler
		),
	)
	server.RegisterService(&authzv1.MyService_ServiceDesc, service)

	// ...
}
```
