package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleTypeIsValid(t *testing.T) {
	tests := []struct {
		role RoleType
		want bool
	}{
		{RoleNone, true},
		{RoleViewer, true},
		{RoleEditor, true},
		{RoleAdmin, true},
		{"", false},
		{"Unknown", false},
		{"viewer", false},
		{"ADMIN", false},
		{" Admin ", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.role.IsValid())
		})
	}
}

func TestRoleTypeIncludes(t *testing.T) {
	roles := []RoleType{RoleNone, RoleViewer, RoleEditor, RoleAdmin, "", "Unknown"}
	tests := []struct {
		role RoleType
		want []bool
	}{
		{RoleNone, []bool{true, false, false, false, true, true}},
		{RoleViewer, []bool{true, true, false, false, true, true}},
		{RoleEditor, []bool{true, true, true, false, true, true}},
		{RoleAdmin, []bool{true, true, true, true, true, true}},
		{"", []bool{false, false, false, false, true, true}},
		{"Unknown", []bool{false, false, false, false, true, true}},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			for i, other := range roles {
				t.Run(string(other), func(t *testing.T) {
					assert.Equal(t, tt.want[i], tt.role.Includes(other))
				})
			}
		})
	}
}

func TestRoleTypeChildren(t *testing.T) {
	tests := []struct {
		role RoleType
		want []RoleType
	}{
		{RoleNone, []RoleType{}},
		{RoleViewer, []RoleType{RoleNone}},
		{RoleEditor, []RoleType{RoleNone, RoleViewer}},
		{RoleAdmin, []RoleType{RoleNone, RoleViewer, RoleEditor}},
		{"", []RoleType{}},
		{"Unknown", []RoleType{}},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.role.Children())
		})
	}
}

func TestRoleTypeParents(t *testing.T) {
	tests := []struct {
		role RoleType
		want []RoleType
	}{
		{RoleNone, []RoleType{RoleViewer, RoleEditor, RoleAdmin}},
		{RoleViewer, []RoleType{RoleEditor, RoleAdmin}},
		{RoleEditor, []RoleType{RoleAdmin}},
		{RoleAdmin, []RoleType{}},
		{"", []RoleType{RoleNone, RoleViewer, RoleEditor, RoleAdmin}},
		{"Unknown", []RoleType{RoleNone, RoleViewer, RoleEditor, RoleAdmin}},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.role.Parents())
		})
	}
}

func TestRoleTypeUnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    RoleType
		wantErr string
	}{
		{name: "none", data: []byte("None"), want: RoleNone},
		{name: "viewer", data: []byte("Viewer"), want: RoleViewer},
		{name: "editor", data: []byte("Editor"), want: RoleEditor},
		{name: "admin", data: []byte("Admin"), want: RoleAdmin},
		{name: "lowercase none", data: []byte("none"), want: RoleNone},
		{name: "lowercase viewer", data: []byte("viewer"), want: RoleViewer},
		{name: "lowercase editor", data: []byte("editor"), want: RoleEditor},
		{name: "lowercase admin", data: []byte("admin"), want: RoleAdmin},
		{name: "empty defaults to viewer", data: []byte(""), want: RoleViewer},
		{name: "nil defaults to viewer", data: nil, want: RoleViewer},
		{
			name:    "unknown role",
			data:    []byte("unknown"),
			want:    "Unknown",
			wantErr: "invalid role value: Unknown",
		},
		{
			name:    "uppercase role",
			data:    []byte("VIEWER"),
			want:    "VIEWER",
			wantErr: "invalid role value: VIEWER",
		},
		{
			name:    "mixed case role",
			data:    []byte("vIeWeR"),
			want:    "VIeWeR",
			wantErr: "invalid role value: VIeWeR",
		},
		{
			name:    "surrounding whitespace",
			data:    []byte(" viewer "),
			want:    " viewer ",
			wantErr: "invalid role value:  viewer ",
		},
		{
			name:    "whitespace does not default to viewer",
			data:    []byte(" "),
			want:    " ",
			wantErr: "invalid role value:  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := RoleAdmin
			err := role.UnmarshalText(tt.data)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, role)
		})
	}
}
