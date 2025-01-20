package types_test

import (
	"testing"

	"github.com/grafana/authlib/types"
)

func TestParseNamespace(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		expected  types.NamespaceInfo
		expectErr bool
	}{
		{
			name: "empty namespace",
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "incorrect number of parts",
			namespace: "org-123-a",
			expectErr: true,
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "org id not a number",
			namespace: "org-invalid",
			expectErr: true,
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "valid org id",
			namespace: "org-123",
			expected: types.NamespaceInfo{
				OrgID: 123,
			},
		},
		{
			name:      "org should not be 1 in the namespace",
			namespace: "org-1",
			expectErr: true,
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "can not be negative",
			namespace: "org--5",
			expectErr: true,
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "can not be zero",
			namespace: "org-0",
			expectErr: true,
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "default is org 1",
			namespace: "default",
			expected: types.NamespaceInfo{
				OrgID: 1,
			},
		},
		{
			name:      "invalid stack id (must be an int)",
			expectErr: true,
			namespace: "stacks-abcdef",
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "invalid stack id in deprecated claim (must be an int)",
			expectErr: true,
			namespace: "stack-abcdef",
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "invalid stack id (must be provided)",
			namespace: "stacks-",
			expectErr: true,
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "invalid stack id (cannot be 0)",
			namespace: "stacks-0",
			expectErr: true,
			expected: types.NamespaceInfo{
				OrgID: -1,
			},
		},
		{
			name:      "valid stack",
			namespace: "stacks-1",
			expected: types.NamespaceInfo{
				OrgID:   1,
				StackID: 1,
			},
		},
		{
			name:      "valid stack is read from deprecated claim",
			namespace: "stack-1",
			expected: types.NamespaceInfo{
				OrgID:   1,
				StackID: 1,
			},
		},
		{
			name:      "other namespace",
			namespace: "anything",
			expected: types.NamespaceInfo{
				OrgID: -1,
				Value: "anything",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := types.ParseNamespace(tt.namespace)
			if tt.expectErr != (err != nil) {
				t.Errorf("ParseNamespace() returned %+v, expected an error", info)
			}
			if info.OrgID != tt.expected.OrgID {
				t.Errorf("ParseNamespace() [OrgID] returned %d, expected %d", info.OrgID, tt.expected.OrgID)
			}
			if info.StackID != tt.expected.StackID {
				t.Errorf("ParseNamespace() [StackID] returned %d, expected %d", info.StackID, tt.expected.StackID)
			}
			if info.Value != tt.namespace {
				t.Errorf("ParseNamespace() [Value] returned %s, expected %s", info.Value, tt.namespace)
			}
		})
	}
}
