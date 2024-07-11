package authz

import (
	"testing"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/stretchr/testify/require"
)

func TestNewController(t *testing.T) {
	tests := []struct {
		name string
		resp *authzv1.ReadResponse
		want *controller
	}{
		{
			name: "User does not have action",
			resp: &authzv1.ReadResponse{
				Found: false,
				Data:  []*authzv1.ReadResponse_Data{},
			},
			want: &controller{
				Found: false,
			},
		},
		{
			name: "User has a scopeless action",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{},
			},
			want: &controller{Found: true},
		},
		{
			name: "User has the action",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:uid:1"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{"dashboards:uid:1": true},
				Wildcard: map[string]bool{},
			},
		},
		{
			name: "User has the action on a wildcard",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:*"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{},
				Wildcard: map[string]bool{"dashboards": true},
			},
		},
		{
			name: "User has the action on a wildcard and a specific scope",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:*"}, {Object: "dashboards:uid:1"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{"dashboards:uid:1": true},
				Wildcard: map[string]bool{"dashboards": true},
			},
		},
		{
			name: "User has the action on wildcards of different kinds",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:*"}, {Object: "folders:*"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{},
				Wildcard: map[string]bool{"dashboards": true, "folders": true},
			},
		},
		{
			name: "User has the action on the master wildcard",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "*"}},
			},
			want: &controller{
				Found:    true,
				Scopes:   map[string]bool{},
				Wildcard: map[string]bool{"*": true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newController(tt.resp)

			require.Equal(t, tt.want.Found, got.Found)
			require.Len(t, got.Scopes, len(tt.want.Scopes))
			require.Len(t, got.Wildcard, len(tt.want.Wildcard))

			for k, v := range tt.want.Scopes {
				require.Equal(t, v, got.Scopes[k])
			}
			for k, v := range tt.want.Wildcard {
				require.Equal(t, v, got.Wildcard[k])
			}
		})
	}
}

func TestController_Check(t *testing.T) {
	tests := []struct {
		name      string
		ctrl      controller
		resources []Resource
		want      bool
	}{
		{
			name: "User does not have action",
			ctrl: controller{
				Found: false,
			},
			resources: []Resource{},
			want:      false,
		},
		{
			name: "User has a scopeless action",
			ctrl: controller{
				Found: true,
			},
			resources: []Resource{},
			want:      true,
		},
		{
			name: "User has a scopeless action but requested a resource",
			ctrl: controller{
				Found: true,
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      false,
		},
		{
			name: "User has action on a specific scope",
			ctrl: controller{
				Found:  true,
				Scopes: map[string]bool{"dashboards:uid:1": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on a specific scope but not on the requested resource",
			ctrl: controller{
				Found:  true,
				Scopes: map[string]bool{"dashboards:uid:1": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "2"}},
			want:      false,
		},
		{
			name: "User has action on a wildcard",
			ctrl: controller{
				Found:    true,
				Wildcard: map[string]bool{"dashboards": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on a wildcard but not on the requested resource",
			ctrl: controller{
				Found:    true,
				Wildcard: map[string]bool{"dashboards": true},
			},
			resources: []Resource{{Kind: "folders", Attr: "uid", ID: "1"}},
			want:      false,
		},
		{
			name: "User has action on the master wildcard",
			ctrl: controller{
				Found:    true,
				Wildcard: map[string]bool{"*": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on one of the requested resources",
			ctrl: controller{
				Found:    true,
				Scopes:   map[string]bool{"folders:uid:1": true},
				Wildcard: map[string]bool{},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}, {Kind: "folders", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on none of the requested resources",
			ctrl: controller{
				Found:    true,
				Scopes:   map[string]bool{"folders:uid:2": true},
				Wildcard: map[string]bool{},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}, {Kind: "folders", Attr: "uid", ID: "1"}},
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ctrl.Check(tt.resources...)
			require.Equal(t, tt.want, got)
		})
	}
}
