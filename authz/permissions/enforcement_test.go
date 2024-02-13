package permissions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/authz"
	"github.com/grafana/authlib/authz/api"
	"github.com/grafana/authlib/authz/testutils"
)

func TestEnforcementClientImpl_fetchPermissions_queryPreload(t *testing.T) {
	tests := []struct {
		name         string
		idToken      string
		action       string
		resource     *authz.Resource
		preloadQuery *api.SearchQuery
		wantQuery    api.SearchQuery
	}{
		{
			name:     "without preload query",
			idToken:  "jwt_id_token",
			action:   "teams:read",
			resource: &authz.Resource{Kind: "teams", Attr: "id", ID: "1"},
			wantQuery: api.SearchQuery{
				IdToken:  "jwt_id_token",
				Action:   "teams:read",
				Resource: &authz.Resource{Kind: "teams", Attr: "id", ID: "1"},
			},
		},
		{
			name:     "with preload query",
			idToken:  "jwt_id_token",
			action:   "teams:read",
			resource: &authz.Resource{Kind: "teams", Attr: "id", ID: "1"},
			preloadQuery: &api.SearchQuery{
				ActionPrefix: "teams",
			},
			wantQuery: api.SearchQuery{
				ActionPrefix: "teams",
				IdToken:      "jwt_id_token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &testutils.MockClient{}
			s := NewEnforcementClient(mockClient)
			if tt.preloadQuery != nil {
				s.preload = tt.preloadQuery
			}
			mockClient.On("Search", mock.Anything, tt.wantQuery).Return(&api.SearchResponse{Data: &api.PermissionsByID{}}, nil)

			_, err := s.fetchPermissions(context.Background(), tt.idToken, tt.action, tt.resource)
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
		resource    *authz.Resource
		wantQuery   api.SearchQuery
		want        bool
	}{
		{
			name:    "no permission",
			idToken: "jwt_id_token",
			action:  "teams:read",
			wantQuery: api.SearchQuery{
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
			wantQuery: api.SearchQuery{
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
			wantQuery: api.SearchQuery{
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
			resource:    &authz.Resource{Kind: "teams", Attr: "id", ID: "1"},
			wantQuery: api.SearchQuery{
				IdToken:  "jwt_id_token",
				Action:   "teams:read",
				Resource: &authz.Resource{Kind: "teams", Attr: "id", ID: "1"},
			},
			want: true,
		},
		{
			name:        "does not have action on scope",
			permissions: map[string][]string{"teams:read": {"teams:id:1", "teams:id:2"}}, // only likely with query preload
			idToken:     "jwt_id_token",
			action:      "teams:read",
			resource:    &authz.Resource{Kind: "teams", Attr: "id", ID: "3"},
			wantQuery: api.SearchQuery{
				IdToken:  "jwt_id_token",
				Action:   "teams:read",
				Resource: &authz.Resource{Kind: "teams", Attr: "id", ID: "3"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &testutils.MockClient{}
			mockClient.On("Search", mock.Anything, tt.wantQuery).Return(&api.SearchResponse{Data: &api.PermissionsByID{1: tt.permissions}}, nil)
			s := NewEnforcementClient(mockClient)
			got, err := s.HasAccess(context.Background(), tt.idToken, tt.action, tt.resource)
			require.NoError(t, err)
			require.Equal(t, got, tt.want)
		})
	}
}
