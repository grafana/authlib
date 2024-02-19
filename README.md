# rbac-client

This is an RBAC client library that contains a set of utilities to fetch and check users permissions from Grafana.

## Grafana Configuration

Grafana needs to be configured with the `accessControlOnCall` feature toggle set for the search permissions endpoint to be registered.

```ini
[feature_toggles]
enable = accessControlOnCall 
```

## Examples

### client usage

This repository is private for now, to use the library:
```bash
GOPRIVATE=github.com/grafana/authlib
```

Here is an example on how to fetch a user's permission filtering on a specific action `users:read`.

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/grafana/rbac-client-poc/pkg/ac/cache"
	"github.com/grafana/rbac-client-poc/pkg/ac/client"
)

func main() {
	c, err := client.NewRBACClient(client.ClientCfg{
		GrafanaURL: "http://localhost:3000",
		Token:      "Your Service Account Token",
	})
	if err != nil {
		fmt.Printf("Error creating client %v\n", err)
	}

	perms, err := c.SearchUserPermissions(context.Background(), client.SearchQuery{
		Action: "users:read",
		UserLogin: "admin",
	})
	if err != nil {
		fmt.Printf("Error fetching permissions %v\n", err)
	}

	fmt.Println("Got permissions from Grafana", perms)
}
```

The program here would output:
```
Got permissions from Grafana map[1:map[users:read:[global.users:*]]]
```

More filters are available to search `userLogin`, `userId`, `action`, `actionPrefix`, `scope`.

### checker usage (to search and filter)


```go
package main

import (
	"context"
	"fmt"

	"github.com/grafana/rbac-client-poc/pkg/ac/checker"
	"github.com/grafana/rbac-client-poc/pkg/ac/models"
)

type dash struct {
	uid       string
	parentUid string
}

func main() {
	userPermissions := models.Permissions{
		"dashboards:read": {"dashboards:uid:dashAABBCC", "folders:uid:foldCCDDEE"},
	}

	canRead := checker.GenerateChecker(context.Background(), userPermissions, "dashboards:read", "dashboards:uid:", "folders:uid:")

	dashboards := []dash{
		{uid: "dashAABBCC", parentUid: "foldAABBCC"},
		{uid: "dashBBCCDD", parentUid: "foldBBCCDD"},
		{uid: "dashCCDDEE", parentUid: "foldCCDDEE"},
	}

	for i := range dashboards {
		if canRead("dashboards:uid:"+dashboards[i].uid) || canRead("folders:uid:"+dashboards[i].parentUid) {
			fmt.Printf("OK: %v\n", dashboards[i].uid)
			continue
		}
		fmt.Printf("KO: %v\n", dashboards[i].uid)
	}
}
```

The program here would output:
```
OK: dashAABBCC
KO: dashBBCCDD
OK: dashCCDDEE
```

Here is an example on how to fetch a user's permission by `idToken`, presuming the `idForwarding` feature toggle is enabled.
```go
func main() {
	grafanaURL := "localhost:3000"

	ac, err := authz.NewClient(authz.Config{
		APIURL:  grafanaURL,
		Token:   "Your Grafana Token",
		JWKsURL: strings.TrimRight(grafanaURL, "/") + "/api/signing-keys/keys",
	})
	if err != nil {
		fmt.Printf("Error creating client %v\n", err)
	}

	idToken := req.Headers.Get("X-Grafana-Id")

	permResp, err := ac.Search(context, authz.SearchQuery{
		IdToken: idToken,
	})

	userPermissions := authz.Permissions{}
	
	for _, permissions := range *permResp.Data {
		userPermissions = permissions
	}

}
```
