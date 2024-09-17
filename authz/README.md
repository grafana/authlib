# Authz

##

This package exports an RBAC client library that contains a set of utilities to check users permissions from Grafana.

## Grafana Configuration

Grafana needs to be configured with the `accessControlOnCall` feature toggle set for the search permissions endpoint to be registered.

```ini
[feature_toggles]
enable = accessControlOnCall
```

## Examples

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
