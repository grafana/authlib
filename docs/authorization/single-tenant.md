## How it works for Grafana Plugins

This library empowers your Grafana plugins with straightforward access control mechanisms using the `EnforcementClient`. This client simplifies the enforcement of Grafana's Role-Based Access Control (RBAC) within your plugin.

## Example: Check if a user can read a specific user

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

## Implementation Guidance:**

For a comprehensive guide on implementing RBAC access control in your Grafana plugins, refer to our detailed example: [https://github.com/grafana/grafana-plugin-examples/blob/main/examples/app-with-rbac/README.md](https://github.com/grafana/grafana-plugin-examples/blob/main/examples/app-with-rbac/README.md).

**Features**:

- Single-tenant RBAC client, typically used by plugins to query Grafana for user permissions and control their access.
- **[unstable / under development]** Multi-tenant client, typically used by multi-tenant applications to enforce service and user access.
