# Authlib

A collection of common authn/authz utilities.

## Authz

This package exports an RBAC client library that contains a set of utilities to check users permissions from Grafana.

## Grafana Configuration

Grafana needs to be configured with the `accessControlOnCall` feature toggle set for the search permissions endpoint to be registered.

```ini
[feature_toggles]
enable = accessControlOnCall 
```

## Examples

This repository is private for now, to use the library:
```bash
GOPRIVATE=github.com/grafana/authlib
```

Here is an example on how to check access on a resouce for a user.

```go
package main

import (
	"context"
	"log"

	"github.com/grafana/authlib/authz"
)

func main() {
	client, err := authz.NewEnforcementClient(authz.Config{
		APIURL:  "http://localhost:3000",
		Token:   "<service account token>",
		JWKsURL: "<jwks url>",
	})

	if err != nil {
		log.Fatal("failed to construct authz client", err)
	}

	ok, err := client.HasAccess(context.Background(), "<id token>", "users:read", authz.Resource{
		Kind: "users",
		Attr: "id",
		ID:   "1",
	})

	if err != nil {
		log.Fatal("failed to perform access check", err)
	}

	log.Println("has access: ", ok)
}
```

## Authn

This package exports an token verifier that can be used to verify signed jwt tokens. A common usecase for this component is to verify grafana id tokens.

This package will handle retrival and caching of jwks. It was designed to be generic over "Custom claims" so that we are not restricted to the current structure of id tokens. This means that the parsed claims will contain standard jwts claims such as `aud`, `exp` etc plus specified custom claims.

## Example

```go
package main

import (
	"context"
	"log"

	"github.com/grafana/authlib/authn"
)

type CustomClaims struct{}

func main() {
	verifier := authn.NewVerifier[CustomClaims](authn.IDVerifierConfig{
		SigningKeysURL:   "<jwks url>",
		AllowedAudiences: []string{},
	})

	claims, err := verifier.Verify(context.Background(), "<token>")

	if err != nil {
		log.Fatal("failed to verify id token: ", err)
	}

	log.Println("Claims: ", claims)
}

```
