package permissions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/authz"
)

func Test_WildcardsDetector(t *testing.T) {
	tests := []struct {
		name  string
		kinds []string
		scope string
		want  bool
	}{
		{
			name:  "no kind",
			kinds: []string{},
			scope: "*",
			want:  false,
		},
		{ // edge case that should not happen
			name:  "empty kind",
			kinds: []string{""},
			scope: "datasources:uid:*",
			want:  false,
		},
		{ // edge case only the ultra wildcard can be a wildcard for empty kind
			name:  "empty kind ultra wildcard",
			kinds: []string{""},
			scope: "*",
			want:  true,
		},
		{
			name:  "is utlra wildcard",
			kinds: []string{"datasources"},
			scope: "*",
			want:  true,
		},
		{
			name:  "is wildcard",
			kinds: []string{"datasources"},
			scope: "datasources:uid:*",
			want:  true,
		},
		{
			name:  "not a wildcard",
			kinds: []string{"datasources"},
			scope: "datasources:uid:1",
			want:  false,
		},
		{
			name:  "wildcard of another kind",
			kinds: []string{"datasources"},
			scope: "folders:uid:*",
			want:  false,
		},
		{
			name:  "edge case ignore attribute",
			kinds: []string{"datasources"},
			scope: "datasources:name:*",
			want:  true,
		},
		{
			name:  "two kinds",
			kinds: []string{"datasources", "folders"},
			scope: "datasources:uid:*",
			want:  true,
		},
		{
			name:  "two kinds",
			kinds: []string{"datasources", "folders"},
			scope: "folders:uid:*",
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, WildcardDetector(tt.kinds...)(tt.scope))
		})
	}
}

func TestGenerateChecker(t *testing.T) {
	userPermissions := authz.Permissions{
		"dashboards:create": []string{},                                                                         // no scope
		"dashboards:read":   []string{"dashboards:uid:*", "folders:uid:*"},                                      // wildcards
		"dashboards:write":  []string{"dashboards:uid:1", "dashboards:uid:2", "folders:uid:3", "folders:uid:4"}, // folders or dashboards
		"dashboards:delete": []string{"folders:uid:3"},                                                          // should have no scope
	}

	type match struct {
		resources []authz.Resource
		hasAccess bool
	}
	tests := []struct {
		name        string
		permissions authz.Permissions
		action      string
		prefixes    []string
		want        match
	}{
		{
			name:        "no match user has no permission",
			permissions: authz.Permissions{},
			action:      "dashboards:read",
			prefixes:    []string{"dashboards:uid"},
			want:        match{resources: []authz.Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}}, hasAccess: false},
		},
		{
			name:        "no match user does not have the permission",
			permissions: userPermissions,
			action:      "folders:read",
			prefixes:    []string{"folders:uid"},
			want:        match{resources: []authz.Resource{{Kind: "folders", Attr: "uid", ID: "2"}}, hasAccess: false},
		},
		{
			name:        "match on action only",
			permissions: userPermissions,
			action:      "dashboards:create",
			prefixes:    []string{},
			want:        match{resources: []authz.Resource{}, hasAccess: true},
		},
		{
			name:        "no match on action only",
			permissions: userPermissions,
			action:      "dashboards:print",
			prefixes:    []string{},
			want:        match{resources: []authz.Resource{}, hasAccess: false},
		},
		{
			name:        "match on action only even with scope",
			permissions: userPermissions,
			action:      "dashboards:delete",
			prefixes:    []string{},
			want:        match{resources: []authz.Resource{}, hasAccess: true},
		},
		{
			name:        "match user has specific permission",
			permissions: userPermissions,
			action:      "dashboards:write",
			prefixes:    []string{"dashboards:uid"},
			want:        match{resources: []authz.Resource{{Kind: "dashboards", Attr: "uid", ID: "2"}}, hasAccess: true},
		},
		{
			name:        "match user has wildcard permission",
			permissions: userPermissions,
			action:      "dashboards:read",
			prefixes:    []string{"dashboards:uid"},
			want:        match{resources: []authz.Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}}, hasAccess: true},
		},
		{
			name:        "no match user has action but on none of the desired",
			permissions: userPermissions,
			action:      "dashboards:write",
			prefixes:    []string{"dashboards:uid"},
			want: match{resources: []authz.Resource{
				{Kind: "dashboards", Attr: "uid", ID: "55"},
				{Kind: "dashboards", Attr: "uid", ID: "56"},
			}, hasAccess: false},
		},
		{
			name:        "match checker built with multiple prefixes",
			permissions: userPermissions,
			action:      "dashboards:write",
			prefixes:    []string{"dashboards:uid", "folders:uid"},
			want: match{resources: []authz.Resource{
				{Kind: "dashboards", Attr: "uid", ID: "55"},
				{Kind: "folders", Attr: "uid", ID: "3"},
			}, hasAccess: true},
		},
		{
			name:        "match when at least one scope is found",
			permissions: userPermissions,
			action:      "dashboards:write",
			prefixes:    []string{"dashboards:uid"},
			want: match{resources: []authz.Resource{
				{Kind: "dashboards", Attr: "uid", ID: "55"},
				{Kind: "dashboards", Attr: "uid", ID: "2"},
			}, hasAccess: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := CompileChecker(tt.permissions, tt.action, tt.prefixes...)
			got := checker(tt.want.resources...)
			require.Equal(t, tt.want.hasAccess, got)
		})
	}
}

func TestCheckerExamples(t *testing.T) {
	type dashboard struct {
		UID       string
		parentUID string
	}

	userPermissions := authz.Permissions{
		"dashboards:create": []string{},
		"dashboards:read":   []string{"dashboards:uid:*", "folders:uid:*"},
		"dashboards:write":  []string{"dashboards:uid:dash1", "dashboards:uid:dash2", "folders:uid:fold1", "folders:uid:fold2"},
	}

	dashboards := []dashboard{
		{UID: "dash1", parentUID: "fold1"}, // Can write dash directly and through folder
		{UID: "dash2", parentUID: "fold3"}, // Can write dash directly
		{UID: "dash3", parentUID: "fold2"}, // Can write dash through folder
		{UID: "dash4", parentUID: "fold3"}, // Cannot write dash
	}

	// Check on action only
	canCreateDashboards := CompileChecker(userPermissions, "dashboards:create")
	require.True(t, canCreateDashboards())
	canDeleteDashboards := CompileChecker(userPermissions, "dashboards:delete")
	require.False(t, canDeleteDashboards())

	// Check on either dashboard or folder
	canReadDashboards := CompileChecker(userPermissions, "dashboards:read", "dashboards:uid", "folders:uid")
	dash2 := authz.Resource{Kind: "dashboards", Attr: "uid", ID: "dash2"}
	require.True(t, canReadDashboards(dash2), "should be allowed to read dashboard")
	fold2 := authz.Resource{Kind: "folders", Attr: "uid", ID: "fold2"}
	require.True(t, canReadDashboards(fold2), "should be allowed to read dashboard in the folder")
	dash4 := authz.Resource{Kind: "dashboards", Attr: "uid", ID: "dash4"}
	fold3 := authz.Resource{Kind: "folders", Attr: "uid", ID: "fold3"}
	require.True(t, canReadDashboards(dash4, fold3), "should be allowed to read dashboards in the folder")

	// Filter resources
	canWriteDashboards := CompileChecker(userPermissions, "dashboards:write", "dashboards:uid", "folders:uid")
	writeOK := []string{}
	for _, dash := range dashboards {
		res := authz.Resource{Kind: "dashboards", Attr: "uid", ID: dash.UID}
		parent := authz.Resource{Kind: "folders", Attr: "uid", ID: dash.parentUID}
		if canWriteDashboards(res, parent) {
			writeOK = append(writeOK, dash.UID)
		}
	}
	require.EqualValues(t, []string{"dash1", "dash2", "dash3"}, writeOK)
}
