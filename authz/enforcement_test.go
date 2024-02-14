package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestEnforcementClientImpl_fetchPermissions_queryPreload(t *testing.T) {
	tests := []struct {
		name         string
		idToken      string
		action       string
		resources    []Resource
		preloadQuery *SearchQuery
		wantQuery    SearchQuery
	}{
		{
			name:      "without preload query",
			idToken:   "jwt_id_token",
			action:    "teams:read",
			resources: []Resource{{Kind: "teams", Attr: "id", ID: "1"}},
			wantQuery: SearchQuery{
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
			preloadQuery: &SearchQuery{
				ActionPrefix: "teams",
			},
			wantQuery: SearchQuery{
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
				s.preload = tt.preloadQuery
			}
			mockClient.On("Search", mock.Anything, tt.wantQuery).Return(&SearchResponse{Data: &PermissionsByID{}}, nil)

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
		wantQuery   SearchQuery
		want        bool
	}{
		{
			name:    "no permission",
			idToken: "jwt_id_token",
			action:  "teams:read",
			wantQuery: SearchQuery{
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
			wantQuery: SearchQuery{
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
			wantQuery: SearchQuery{
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
			wantQuery: SearchQuery{
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
			wantQuery: SearchQuery{
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
			wantQuery: SearchQuery{
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
			wantQuery: SearchQuery{
				IdToken: "jwt_id_token",
				Action:  "dashboards:read",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockClient{}
			mockClient.On("Search", mock.Anything, tt.wantQuery).Return(&SearchResponse{Data: &PermissionsByID{1: tt.permissions}}, nil)
			s := EnforcementClientImpl{client: mockClient}

			got, err := s.HasAccess(context.Background(), tt.idToken, tt.action, tt.resources...)
			require.NoError(t, err)
			require.Equal(t, got, tt.want)
		})
	}
}
