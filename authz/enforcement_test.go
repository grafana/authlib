package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestEnforcementClientImpl_fetchPermissions_queryPreload(t *testing.T) {
	tests := []struct {
		name         string
		idToken      string
		action       string
		resources    []Resource
		preloadQuery *searchQuery
		wantQuery    searchQuery
	}{
		{
			name:      "without preload query",
			idToken:   "jwt_id_token",
			action:    "teams:read",
			resources: []Resource{{Kind: "teams", Attr: "id", ID: "1"}},
			wantQuery: searchQuery{
				IdToken:  "jwt_id_token",
				Action:   "teams:read",
				Resource: &Resource{Kind: "teams", Attr: "id", ID: "1"},
			},
		},
		{
			name:      "with preload query",
			idToken:   "jwt_id_token",
			action:    "teams:read",
			resources: []Resource{{Kind: "teams", Attr: "id", ID: "1"}},
			preloadQuery: &searchQuery{
				ActionPrefix: "teams",
			},
			wantQuery: searchQuery{
				ActionPrefix: "teams",
				IdToken:      "jwt_id_token",
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
			mockClient.On("Search", mock.Anything, tt.wantQuery).Return(&searchResponse{Data: &permissionsByID{}}, nil)

			_, err := s.fetchPermissions(context.Background(), tt.idToken, tt.action, tt.resources...)
			require.NoError(t, err)
		})
	}
}

func TestEnforcementClientImpl_HasAccess(t *testing.T) {
	tests := []struct {
		name        string
		permissions map[string][]string
		idToken     string
		action      string
		resources   []Resource
		wantQuery   searchQuery
		want        bool
	}{
		{
			name:    "no permission",
			idToken: "jwt_id_token",
			action:  "teams:read",
			wantQuery: searchQuery{
				IdToken: "jwt_id_token",
				Action:  "teams:read",
			},
			want: false,
		},
		{
			name:        "has action",
			permissions: map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}},
			idToken:     "jwt_id_token",
			action:      "teams:read",
			wantQuery: searchQuery{
				IdToken: "jwt_id_token",
				Action:  "teams:read",
			},
			want: true,
		},
		{
			name:        "does not have action",
			permissions: map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}}, // only likely with query preload
			idToken:     "jwt_id_token",
			action:      "teams:write",
			wantQuery: searchQuery{
				IdToken: "jwt_id_token",
				Action:  "teams:write",
			},
			want: false,
		},
		{
			name:        "has action on scope",
			permissions: map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}},
			idToken:     "jwt_id_token",
			action:      "teams:read",
			resources:   []Resource{{Kind: "teams", Attr: "id", ID: "1"}},
			wantQuery: searchQuery{
				IdToken:  "jwt_id_token",
				Action:   "teams:read",
				Resource: &Resource{Kind: "teams", Attr: "id", ID: "1"},
			},
			want: true,
		},
		{
			name:        "does not have action on scope",
			permissions: map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}}, // only likely with query preload
			idToken:     "jwt_id_token",
			action:      "teams:read",
			resources:   []Resource{{Kind: "teams", Attr: "id", ID: "3"}},
			wantQuery: searchQuery{
				IdToken:  "jwt_id_token",
				Action:   "teams:read",
				Resource: &Resource{Kind: "teams", Attr: "id", ID: "3"},
			},
			want: false,
		},
		{
			name:        "has action on any of the scopes",
			permissions: map[string][]string{"dashboards:read": {"dashboards:uid:1", "folders:uid:2"}},
			idToken:     "jwt_id_token",
			action:      "dashboards:read",
			resources:   []Resource{{Kind: "dashboards", Attr: "uid", ID: "3"}, {Kind: "folders", Attr: "uid", ID: "2"}},
			wantQuery: searchQuery{
				IdToken: "jwt_id_token",
				Action:  "dashboards:read",
			},
			want: true,
		},
		{
			name:        "does not have action on any of the scopes",
			permissions: map[string][]string{"dashboards:read": {"dashboards:uid:1", "folders:uid:2"}},
			idToken:     "jwt_id_token",
			action:      "dashboards:read",
			resources:   []Resource{{Kind: "dashboards", Attr: "uid", ID: "3"}, {Kind: "folders", Attr: "uid", ID: "4"}},
			wantQuery: searchQuery{
				IdToken: "jwt_id_token",
				Action:  "dashboards:read",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockClient{}
			mockClient.On("Search", mock.Anything, tt.wantQuery).Return(&searchResponse{Data: &permissionsByID{1: tt.permissions}}, nil)
			s := EnforcementClientImpl{client: mockClient}

			got, err := s.HasAccess(context.Background(), tt.idToken, tt.action, tt.resources...)
			require.NoError(t, err)
			require.Equal(t, got, tt.want)
		})
	}
}

func TestEnforcementClientImpl_LookupResources(t *testing.T) {
	tests := []struct {
		name        string
		idToken     string
		action      string
		permissions permissionsByID
		want        []Resource
		mockErr     error
		wantErr     bool
	}{
		{
			name:    "no permissions",
			idToken: "jwt_id_token",
			action:  "teams:read",
			permissions: permissionsByID{
				1: map[string][]string{},
			},
			want:    []Resource{},
			wantErr: false,
		},
		{
			name:    "permission filtering works",
			idToken: "jwt_id_token",
			action:  "teams:write",
			permissions: permissionsByID{
				1: map[string][]string{
					"teams:read": {"teams:id:1", "teams:id:2"},
				},
			},
			want:    []Resource{},
			wantErr: false,
		},
		{
			name:    "has permissions",
			idToken: "jwt_id_token",
			action:  "teams:read",
			permissions: permissionsByID{
				1: map[string][]string{
					"teams:read": {"teams:id:1", "teams:id:2"},
				},
			},
			want: []Resource{
				{Kind: "teams", Attr: "id", ID: "1"},
				{Kind: "teams", Attr: "id", ID: "2"},
			},
			wantErr: false,
		},
		{
			name:    "has permissions wildcard",
			idToken: "jwt_id_token",
			action:  "folders:read",
			permissions: permissionsByID{
				1: map[string][]string{
					"folders:read": {"folders:*"},
				},
			},
			want: []Resource{
				{Kind: "folders", Attr: "*", ID: "*"},
			},
			wantErr: false,
		},
		{
			name:        "error fetching permissions",
			idToken:     "jwt_id_token",
			action:      "teams:read",
			permissions: permissionsByID{},
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

			got, err := s.LookupResources(context.Background(), tt.idToken, tt.action)
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
