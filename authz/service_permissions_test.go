package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServicePermissions_SubresourceAliasesAndVerbMapping(t *testing.T) {
	for _, group := range []string{"prometheus.datasource.grafana.app", "loki.datasource.grafana.app", "yesoreyeram-infinity-datasource.datasource.grafana.app"} {
		caller := subresourceCaller([]string{"*.datasource.grafana.app/datasources/query:create"}, false)
		require.True(t, CheckServicePermissions(caller, group, "datasources", "query", "create").Allowed)
		require.False(t, CheckServicePermissions(caller, group, "datasources", "", "create").Allowed)
		require.False(t, CheckServicePermissions(caller, group, "datasources", "caching", "create").Allowed)
	}
	caller := subresourceCaller([]string{"*.datasource.grafana.app/datasources/query:create"}, false)
	for _, group := range []string{"datasource.grafana.app", "bad.loki.datasource.grafana.app", "loki.datasource.grafana.app.evil"} {
		require.False(t, CheckServicePermissions(caller, group, "datasources", "query", "create").Allowed)
	}
	parent := subresourceCaller([]string{"dashboard.grafana.app/dashboards:get"}, false)
	require.True(t, CheckServicePermissions(parent, "dashboard.grafana.app", "dashboards", "", "list").Allowed)
	require.False(t, CheckServicePermissions(parent, "dashboard.grafana.app", "dashboards", "annotations", "list").Allowed)
}

func TestServicePermissions_LegacyActionVerbs(t *testing.T) {
	for _, delegated := range []bool{false, true} {
		caller := subresourceCaller([]string{"*.datasource.grafana.app/datasources:alert.rules.external:read"}, delegated)
		for _, verb := range []string{"alert.rules.external:read", "alert.rules.external:write", "read"} {
			result := CheckServicePermissions(caller, "prometheus.datasource.grafana.app", "datasources", "", verb)
			require.Equal(t, !delegated, result.ServiceCall)
			require.Equal(t, verb == "alert.rules.external:read", result.Allowed)
		}
		require.False(t, CheckServicePermissions(caller, "prometheus.datasource.grafana.app", "datasources", "query", "alert.rules.external:read").Allowed)
	}
}

func TestServicePermissions_LiteralVerbs(t *testing.T) {
	for _, verb := range []string{"get*", "get/extra"} {
		t.Run(verb, func(t *testing.T) {
			caller := subresourceCaller([]string{"group/resource:" + verb}, false)
			require.True(t, CheckServicePermissions(caller, "group", "resource", "", verb).Allowed)
			require.False(t, CheckServicePermissions(caller, "group", "resource", "", "get").Allowed)
			require.False(t, CheckServicePermissions(caller, "group", "resource", "extra", "get").Allowed)
		})
	}
}
