package authz

import (
	"context"
	"testing"

	"github.com/grafana/authlib/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestEnforcementClientImpl_fetchPermissions_queryPreload(t *testing.T) {
	tests := []struct {
		name         string
		namespacedID authn.NamespacedID
		action       string
		resources    []Resource
		preloadQuery *searchQuery
		wantQuery    searchQuery
	}{
		{
			name:         "without preload query",
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "teams:read",
			resources:    []Resource{{Kind: "teams", Attr: "id", ID: "1"}},
			wantQuery: searchQuery{
				NamespacedID: authn.NewNamespacedID("user", 12),
				Action:       "teams:read",
				Resource:     &Resource{Kind: "teams", Attr: "id", ID: "1"},
			},
		},
		{
			name:         "with preload query",
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "teams:read",
			resources:    []Resource{{Kind: "teams", Attr: "id", ID: "1"}},
			preloadQuery: &searchQuery{
				ActionPrefix: "teams",
			},
			wantQuery: searchQuery{
				ActionPrefix: "teams",
				NamespacedID: authn.NewNamespacedID("user", 12),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockClient{}
			s := EnforcementClientImpl{client: mockClient}

			if tt.preloadQuery != nil {
				s.queryTemplate = tt.preloadQuery
			}
			mockClient.On("Search", mock.Anything, tt.wantQuery).Return(&searchResponse{Data: &permissions{}}, nil)

			_, err := s.fetchPermissions(context.Background(), tt.namespacedID, tt.action, tt.resources...)
			require.NoError(t, err)
		})
	}
}

func TestEnforcementClientImpl_HasAccess(t *testing.T) {
	tests := []struct {
		name         string
		permissions  permissions
		namespacedID authn.NamespacedID
		action       string
		resources    []Resource
		wantQuery    searchQuery
		want         bool
	}{
		{
			name:         "no permission",
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "teams:read",
			wantQuery: searchQuery{
				NamespacedID: authn.NewNamespacedID("user", 12),
				Action:       "teams:read",
			},
			want: false,
		},
		{
			name:         "has action",
			permissions:  map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}},
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "teams:read",
			wantQuery: searchQuery{
				NamespacedID: authn.NewNamespacedID("user", 12),
				Action:       "teams:read",
			},
			want: true,
		},
		{
			name:         "does not have action",
			permissions:  map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}}, // only likely with query preload
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "teams:write",
			wantQuery: searchQuery{
				NamespacedID: authn.NewNamespacedID("user", 12),
				Action:       "teams:write",
			},
			want: false,
		},
		{
			name:         "has action on scope",
			permissions:  map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}},
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "teams:read",
			resources:    []Resource{{Kind: "teams", Attr: "id", ID: "1"}},
			wantQuery: searchQuery{
				NamespacedID: authn.NewNamespacedID("user", 12),
				Action:       "teams:read",
				Resource:     &Resource{Kind: "teams", Attr: "id", ID: "1"},
			},
			want: true,
		},
		{
			name:         "does not have action on scope",
			permissions:  map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}}, // only likely with query preload
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "teams:read",
			resources:    []Resource{{Kind: "teams", Attr: "id", ID: "3"}},
			wantQuery: searchQuery{
				NamespacedID: authn.NewNamespacedID("user", 12),
				Action:       "teams:read",
				Resource:     &Resource{Kind: "teams", Attr: "id", ID: "3"},
			},
			want: false,
		},
		{
			name:         "has action on any of the scopes",
			permissions:  map[string][]string{"dashboards:read": {"dashboards:uid:1", "folders:uid:2"}},
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "dashboards:read",
			resources:    []Resource{{Kind: "dashboards", Attr: "uid", ID: "3"}, {Kind: "folders", Attr: "uid", ID: "2"}},
			wantQuery: searchQuery{
				NamespacedID: authn.NewNamespacedID("user", 12),
				Action:       "dashboards:read",
			},
			want: true,
		},
		{
			name:         "does not have action on any of the scopes",
			permissions:  map[string][]string{"dashboards:read": {"dashboards:uid:1", "folders:uid:2"}},
			namespacedID: authn.NewNamespacedID("user", 12),
			action:       "dashboards:read",
			resources:    []Resource{{Kind: "dashboards", Attr: "uid", ID: "3"}, {Kind: "folders", Attr: "uid", ID: "4"}},
			wantQuery: searchQuery{
				NamespacedID: authn.NewNamespacedID("user", 12),
				Action:       "dashboards:read",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockClient{}
			mockClient.On("Search", mock.Anything, tt.wantQuery).Return(&searchResponse{Data: &tt.permissions}, nil)
			s := EnforcementClientImpl{client: mockClient}

			got, err := s.HasAccess(context.Background(), tt.namespacedID, tt.action, tt.resources...)
			require.NoError(t, err)
			require.Equal(t, got, tt.want)
		})
	}
}

func TestEnforcementClientImpl_LookupResources(t *testing.T) {
	tests := []struct {
		name        string
		namespaceID authn.NamespacedID
		action      string
		permissions permissions
		want        []Resource
		mockErr     error
		wantErr     bool
	}{
		{
			name:        "no permissions",
			namespaceID: authn.NewNamespacedID("user", 12),
			action:      "teams:read",
			permissions: permissions{},
			want:        []Resource{},
			wantErr:     false,
		},
		{
			name:        "permission filtering works",
			namespaceID: authn.NewNamespacedID("user", 12),
			action:      "teams:write",
			permissions: permissions{
				"teams:read": {"teams:id:1", "teams:id:2"},
			},
			want:    []Resource{},
			wantErr: false,
		},
		{
			name:        "has permissions",
			namespaceID: authn.NewNamespacedID("user", 12),
			action:      "teams:read",
			permissions: permissions{
				"teams:read": {"teams:id:1", "teams:id:2"},
			},
			want: []Resource{
				{Kind: "teams", Attr: "id", ID: "1"},
				{Kind: "teams", Attr: "id", ID: "2"},
			},
			wantErr: false,
		},
		{
			name:        "has permissions wildcard",
			namespaceID: authn.NewNamespacedID("user", 12),
			action:      "folders:read",
			permissions: permissions{
				"folders:read": {"folders:*"},
			},
			want: []Resource{
				{Kind: "folders", Attr: "*", ID: "*"},
			},
			wantErr: false,
		},
		{
			name:        "error fetching permissions",
			namespaceID: authn.NewNamespacedID("user", 12),
			action:      "teams:read",
			permissions: permissions{},
			mockErr:     ErrTooManyPermissions,
			want:        nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockClient{}
			s := EnforcementClientImpl{client: mockClient}

			mockClient.On("Search", mock.Anything, mock.Anything).Return(&searchResponse{Data: &tt.permissions}, tt.mockErr)

			got, err := s.LookupResources(context.Background(), tt.namespaceID, tt.action)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSplitScope(t *testing.T) {
	tests := []struct {
		name          string
		scope         string
		wantKind      string
		wantAttribute string
		wantID        string
	}{
		{
			name:          "wildcard scope",
			scope:         "*",
			wantKind:      "*",
			wantAttribute: "*",
			wantID:        "*",
		},
		{
			name:          "wildcard scope with specified kind",
			scope:         "dashboards:*",
			wantKind:      "dashboards",
			wantAttribute: "*",
			wantID:        "*",
		},
		{
			name:          "scope with all fields specified",
			scope:         "dashboards:uid:my_dash",
			wantKind:      "dashboards",
			wantAttribute: "uid",
			wantID:        "my_dash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKind, gotAttribute, gotID := splitScope(tt.scope)
			assert.Equal(t, tt.wantKind, gotKind, "they should be equal")
			assert.Equal(t, tt.wantAttribute, gotAttribute, "they should be equal")
			assert.Equal(t, tt.wantID, gotID, "they should be equal")
		})
	}
}
