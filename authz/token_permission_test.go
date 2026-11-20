package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTokenPermission(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  TokenPermission
	}{
		{"dashboard.grafana.app:get", TokenPermission{Group: "dashboard.grafana.app", Verb: "get"}},
		{"g/r:get/extra", TokenPermission{Group: "g", Resource: "r", Verb: "get/extra"}},
		{"g/r:g*", TokenPermission{Group: "g", Resource: "r", Verb: "g*"}},
		{"dashboard.grafana.app/dashboards:*", TokenPermission{Group: "dashboard.grafana.app", Resource: "dashboards", Verb: "*"}},
		{"*.datasource.grafana.app/datasources/query:create", TokenPermission{Group: "*.datasource.grafana.app", Resource: "datasources", Subresource: "query", Verb: "create"}},
		{"*-app/settings:get", TokenPermission{Group: "*-app", Resource: "settings", Verb: "get"}},
		{"*.datasource.grafana.app/datasources:alert.rules.external:read", TokenPermission{Group: "*.datasource.grafana.app", Resource: "datasources", Verb: "alert.rules.external:read"}},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := ParseTokenPermission(tc.input)
			require.True(t, ok)
			require.Equal(t, tc.want, got)
		})
	}
	for _, input := range []string{"", ":get", "g", "g:", "g/:get", "g//s:get", "g/r/:get", "g/r/s/extra:get", "g/*:get", "g/r/*:get", "g/r*:get", "*:get", "*.invalid:get", " g/r:get", "g/r:get\n", "g/r:\x00get", "g/r:\u00a0get"} {
		t.Run(input, func(t *testing.T) {
			got, ok := ParseTokenPermission(input)
			require.False(t, ok)
			require.Empty(t, got)
		})
	}
}
