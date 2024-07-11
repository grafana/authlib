package authz

import (
	"testing"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/stretchr/testify/require"
)

func TestNewReadResult(t *testing.T) {
	tests := []struct {
		name string
		resp *authzv1.ReadResponse
		want *ReadResult
	}{
		{
			name: "User does not have action",
			resp: &authzv1.ReadResponse{
				Found: false,
				Data:  []*authzv1.ReadResponse_Data{},
			},
			want: &ReadResult{
				Found: false,
			},
		},
		{
			name: "User has a scopeless action",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{},
			},
			want: &ReadResult{Found: true},
		},
		{
			name: "User has the action",
			resp: &authzv1.ReadResponse{
				Found: true,
				Data:  []*authzv1.ReadResponse_Data{{Object: "dashboards:uid:1"}},
			},
			want: &ReadResult{
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
			want: &ReadResult{
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
			want: &ReadResult{
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
			want: &ReadResult{
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
			want: &ReadResult{
				Found:    true,
				Scopes:   map[string]bool{},
				Wildcard: map[string]bool{"*": true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewReadResult(tt.resp)

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

func TestReadResult_Check(t *testing.T) {
	tests := []struct {
		name      string
		res       ReadResult
		resources []Resource
		want      bool
	}{
		{
			name: "User does not have action",
			res: ReadResult{
				Found: false,
			},
			resources: []Resource{},
			want:      false,
		},
		{
			name: "User has a scopeless action",
			res: ReadResult{
				Found: true,
			},
			resources: []Resource{},
			want:      true,
		},
		{
			name: "User has a scopeless action but requested a resource",
			res: ReadResult{
				Found: true,
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      false,
		},
		{
			name: "User has action on a specific scope",
			res: ReadResult{
				Found:  true,
				Scopes: map[string]bool{"dashboards:uid:1": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on a specific scope but not on the requested resource",
			res: ReadResult{
				Found:  true,
				Scopes: map[string]bool{"dashboards:uid:1": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "2"}},
			want:      false,
		},
		{
			name: "User has action on a wildcard",
			res: ReadResult{
				Found:    true,
				Wildcard: map[string]bool{"dashboards": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on a wildcard but not on the requested resource",
			res: ReadResult{
				Found:    true,
				Wildcard: map[string]bool{"dashboards": true},
			},
			resources: []Resource{{Kind: "folders", Attr: "uid", ID: "1"}},
			want:      false,
		},
		{
			name: "User has action on the master wildcard",
			res: ReadResult{
				Found:    true,
				Wildcard: map[string]bool{"*": true},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on one of the requested resources",
			res: ReadResult{
				Found:    true,
				Scopes:   map[string]bool{"folders:uid:1": true},
				Wildcard: map[string]bool{},
			},
			resources: []Resource{{Kind: "dashboards", Attr: "uid", ID: "1"}, {Kind: "folders", Attr: "uid", ID: "1"}},
			want:      true,
		},
		{
			name: "User has action on none of the requested resources",
			res: ReadResult{
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
			got := tt.res.Check(tt.resources...)
			require.Equal(t, tt.want, got)
		})
	}
}
