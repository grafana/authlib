package authz

import (
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/grafana/authlib/authn"
)

func TestCheckServicePermissions(t *testing.T) {
	tests := []struct {
		name            string
		subject         string
		claims          authn.AccessTokenClaims
		wantServiceCall bool
		wantAllowed     bool
	}{
		{
			name:            "access policy checks token permissions",
			subject:         "access-policy:abc",
			claims:          authn.AccessTokenClaims{Namespace: "*", Permissions: []string{"dashboard.grafana.app/dashboards:get"}},
			wantServiceCall: true,
			wantAllowed:     true,
		},
		{
			name:            "plugin checks token permissions",
			subject:         "plugin:grafana-example-app",
			claims:          authn.AccessTokenClaims{Namespace: "*", Permissions: []string{"dashboard.grafana.app/dashboards:get"}},
			wantServiceCall: true,
			wantAllowed:     true,
		},
		{
			name:            "plugin is denied what its token does not grant",
			subject:         "plugin:grafana-example-app",
			claims:          authn.AccessTokenClaims{Namespace: "*", Permissions: []string{"dashboard.grafana.app/dashboards:list"}},
			wantServiceCall: true,
			wantAllowed:     false,
		},
		{
			name:    "plugin on behalf of a user checks delegated permissions",
			subject: "plugin:grafana-example-app",
			claims: authn.AccessTokenClaims{
				Namespace:            "stacks-1",
				Permissions:          []string{"dashboard.grafana.app/dashboards:get"},
				DelegatedPermissions: []string{"folder.grafana.app/folders:get"},
				Actor: &authn.ActorClaims{
					Subject:       "user:1",
					IDTokenClaims: authn.IDTokenClaims{Type: "user", Identifier: "1"},
				},
			},
			wantServiceCall: false,
			wantAllowed:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
				Claims: jwt.Claims{Subject: tt.subject},
				Rest:   tt.claims,
			})

			res := CheckServicePermissions(info, "dashboard.grafana.app", "dashboards", "get")
			assert.Equal(t, tt.wantServiceCall, res.ServiceCall)
			assert.Equal(t, tt.wantAllowed, res.Allowed)
		})
	}
}
