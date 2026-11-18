package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Kind-scoped wildcard behavior for compileChecker and EnforcementClientImpl.Compile.
// A wildcard grants every identifier of its own kind. It must not allow a resource
// of another kind, and specific scopes of the other kinds must still be honored.
// These tests fail while one wildcard scope selects the allow-all checker.

func TestCompileCheckerFolderWildcardDoesNotAllowDashboardAlone(t *testing.T) {
	// Folder-aware checker shape used by TestCheckerExamples: one checker for
	// dashboards and folders, then a dashboard evaluated by itself.
	otherDash := Resource{Kind: "dashboards", Attr: "uid", ID: "dash4"}
	grantedDash := Resource{Kind: "dashboards", Attr: "uid", ID: "dash1"}
	foreignFolder := Resource{Kind: "folders", Attr: "uid", ID: "fold3"}
	otherKind := Resource{Kind: "playlists", Attr: "uid", ID: "playlist-1"}

	tests := []struct {
		name      string
		scopes    []string
		perms     permissions
		kinds     []string
		resources []Resource
		want      bool
	}{
		{
			name:      "folder uid wildcard denies a dashboard checked alone",
			scopes:    []string{"folders:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash},
			want:      false,
		},
		{
			name:      "folder uid wildcard allows any folder",
			scopes:    []string{"folders:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{foreignFolder},
			want:      true,
		},
		{
			name:      "folder uid wildcard allows a dashboard when its folder is checked too",
			scopes:    []string{"folders:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash, foreignFolder},
			want:      true,
		},
		{
			name:      "folder uid wildcard denies a kind that was not compiled",
			scopes:    []string{"folders:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherKind},
			want:      false,
		},
		{
			name:      "folder uid wildcard denies an empty resource list",
			scopes:    []string{"folders:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: nil,
			want:      false,
		},
		{
			name:      "folder star scope denies a dashboard checked alone",
			scopes:    []string{"folders:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash},
			want:      false,
		},
		{
			name:      "folder star scope allows any folder",
			scopes:    []string{"folders:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{foreignFolder},
			want:      true,
		},
		{
			name:      "folder name wildcard is kind-wide and denies a dashboard",
			scopes:    []string{"folders:name:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash},
			want:      false,
		},
		{
			name:      "folder name wildcard allows a folder with a different attribute",
			scopes:    []string{"folders:name:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{foreignFolder},
			want:      true,
		},
		{
			name:      "specific dashboard after a folder wildcard stays allowed",
			scopes:    []string{"folders:uid:*", "dashboards:uid:dash1"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{grantedDash},
			want:      true,
		},
		{
			name:      "specific dashboard before a folder wildcard stays allowed",
			scopes:    []string{"dashboards:uid:dash1", "folders:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{grantedDash},
			want:      true,
		},
		{
			name:      "folder wildcard does not widen the specific dashboard grant",
			scopes:    []string{"dashboards:uid:dash1", "folders:uid:fold1", "folders:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash},
			want:      false,
		},
		{
			name:      "dashboard uid wildcard denies a folder checked alone",
			scopes:    []string{"dashboards:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{foreignFolder},
			want:      false,
		},
		{
			name:      "dashboard uid wildcard allows any dashboard",
			scopes:    []string{"dashboards:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash},
			want:      true,
		},
		{
			name:      "dashboard star scope denies a folder",
			scopes:    []string{"dashboards:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{foreignFolder},
			want:      false,
		},
		{
			name:      "dashboard wildcard keeps a specific folder scope",
			scopes:    []string{"dashboards:uid:*", "folders:uid:fold3"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{foreignFolder},
			want:      true,
		},
		{
			name:      "dashboard wildcard does not allow a different folder",
			scopes:    []string{"folders:uid:fold1", "dashboards:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{foreignFolder},
			want:      false,
		},
		{
			name:      "ultra wildcard still allows a dashboard",
			scopes:    []string{"*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash},
			want:      true,
		},
		{
			name:      "ultra wildcard still allows a folder",
			scopes:    []string{"*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{foreignFolder},
			want:      true,
		},
		{
			name:      "kind star scope still allows every compiled kind",
			scopes:    []string{"*:uid:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash},
			want:      true,
		},
		{
			name:      "star inside an identifier is an exact scope",
			scopes:    []string{"dashboards:uid:1:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "other"}},
			want:      false,
		},
		{
			name:      "star inside an identifier still matches that exact resource",
			scopes:    []string{"dashboards:uid:1:*"},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1:*"}},
			want:      true,
		},
		{
			name:      "folder wildcard is ignored when folders is not a compiled kind",
			scopes:    []string{"folders:uid:*", "dashboards:uid:dash1"},
			kinds:     []string{"dashboards"},
			resources: []Resource{otherDash},
			want:      false,
		},
		{
			name: "wildcard on a different action does not apply",
			perms: permissions{
				"dashboards:write": {"folders:uid:*"},
				"dashboards:read":  {"dashboards:uid:dash1"},
			},
			kinds:     []string{"dashboards", "folders"},
			resources: []Resource{otherDash},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := tt.perms
			if perms == nil {
				perms = permissions{"dashboards:read": tt.scopes}
			}
			checker := compileChecker(perms, "dashboards:read", tt.kinds...)
			require.Equal(t, tt.want, checker(tt.resources...))
		})
	}
}

func TestEnforcementCompileFolderWildcardDoesNotAllowDashboardAlone(t *testing.T) {
	otherDash := Resource{Kind: "dashboards", Attr: "uid", ID: "dash4"}
	grantedDash := Resource{Kind: "dashboards", Attr: "uid", ID: "dash1"}
	foreignFolder := Resource{Kind: "folders", Attr: "uid", ID: "fold3"}

	t.Run("compile then check a dashboard the folder wildcard does not name", func(t *testing.T) {
		checker := compileAction(t, "dashboards:read", []string{"folders:uid:*", "dashboards:uid:dash1"}, "dashboards", "folders")

		require.False(t, checker(otherDash))
		require.True(t, checker(grantedDash))
		require.True(t, checker(foreignFolder))
		require.True(t, checker(otherDash, foreignFolder))
		// A later call must not reuse an allow-all result from the folder call.
		require.False(t, checker(otherDash))
	})

	t.Run("compile with a dashboard wildcard then check a folder", func(t *testing.T) {
		checker := compileAction(t, "dashboards:read", []string{"dashboards:uid:*", "folders:uid:fold1"}, "dashboards", "folders")

		require.True(t, checker(otherDash))
		require.False(t, checker(foreignFolder))
		require.True(t, checker(Resource{Kind: "folders", Attr: "uid", ID: "fold1"}))
	})
}

func TestEnforcementHasAccessWildcardStaysOnTheCheckedKind(t *testing.T) {
	// HasAccess derives kinds from the resources it evaluates, so a folder
	// wildcard cannot widen a dashboard-only check. These expectations hold
	// before and after kind-scoped compilation.
	otherDash := Resource{Kind: "dashboards", Attr: "uid", ID: "dash4"}
	grantedDash := Resource{Kind: "dashboards", Attr: "uid", ID: "dash1"}
	foreignFolder := Resource{Kind: "folders", Attr: "uid", ID: "fold3"}
	perms := map[string][]string{
		"dashboards:read": {"folders:uid:*", "dashboards:uid:dash1"},
	}

	t.Run("dashboard alone", func(t *testing.T) {
		require.False(t, hasAccess(t, perms, "dashboards:read", otherDash))
		require.True(t, hasAccess(t, perms, "dashboards:read", grantedDash))
	})

	t.Run("folder alone", func(t *testing.T) {
		require.True(t, hasAccess(t, perms, "dashboards:read", foreignFolder))
	})

	t.Run("dashboard and folder", func(t *testing.T) {
		require.True(t, hasAccess(t, perms, "dashboards:read", otherDash, foreignFolder))
	})

	t.Run("dashboard wildcard does not allow a folder checked alone", func(t *testing.T) {
		dashboardWildcard := map[string][]string{
			"dashboards:read": {"dashboards:uid:*"},
		}
		require.False(t, hasAccess(t, dashboardWildcard, "dashboards:read", foreignFolder))
		require.True(t, hasAccess(t, dashboardWildcard, "dashboards:read", otherDash))
	})
}

func compileAction(t *testing.T, action string, scopes []string, kinds ...string) Checker {
	t.Helper()

	mockClient := &MockClient{}
	mockClient.On("Search", mock.Anything, searchQuery{
		IdToken: "test-id-token",
		Action:  action,
	}).Return(&searchResponse{Data: &permissionsByID{
		1: {action: scopes},
	}}, nil)

	client := EnforcementClientImpl{client: mockClient}
	checker, err := client.Compile(context.Background(), "test-id-token", action, kinds...)
	require.NoError(t, err)
	mockClient.AssertExpectations(t)
	return checker
}

func hasAccess(t *testing.T, perms map[string][]string, action string, resources ...Resource) bool {
	t.Helper()

	query := searchQuery{
		IdToken: "test-id-token",
		Action:  action,
	}
	if len(resources) == 1 {
		res := resources[0]
		query.Resource = &res
	}

	mockClient := &MockClient{}
	mockClient.On("Search", mock.Anything, query).Return(&searchResponse{Data: &permissionsByID{
		1: perms,
	}}, nil)

	client := EnforcementClientImpl{client: mockClient}
	allowed, err := client.HasAccess(context.Background(), "test-id-token", action, resources...)
	require.NoError(t, err)
	mockClient.AssertExpectations(t)
	return allowed
}
