package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"
)

func TestClient_LegacyGetUserPermissionsRejectsInvalidCallers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		caller types.AuthInfo
		want   error
	}{
		{"nil", nil, ErrMissingAuthInfo},
		{"no grant", legacyCaller("stacks-12"), ErrLegacyUserPermissionsDenied},
		{"old grant only", legacyCaller("stacks-12", "authz.grafana.app/userpermissions:get"), ErrLegacyUserPermissionsDenied},
		{"other namespace", legacyCaller("stacks-13", "authz.grafana.app/legacyuserpermissions:get"), ErrNamespaceMismatch},
		{"delegated identity", legacyDelegatedCaller{legacyCaller("stacks-12")}, ErrLegacyUserPermissionsDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := &legacyTestRPC{}
			client := &LegacyClient{clientV1: rpc, tracer: noop.Tracer{}}
			got, err := client.LegacyGetUserPermissions(t.Context(), tc.caller, legacyRequest())
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, got.Permissions)
			require.Zero(t, rpc.calls)
		})
	}
}

func TestClient_LegacyGetUserPermissionsEvaluationScope(t *testing.T) {
	for _, tc := range []struct {
		name, namespace string
		valid           bool
	}{
		{"cloud", "stacks-12", true},
		{"default org", "default", true},
		{"other org", "org-2", true},
		{"wildcard", "*", false},
		{"empty namespace", "", false},
		{"invented global namespace", "org-0", false},
		{"negative org", "org--1", false},
		{"invalid stack", "stacks-zero", false},
		{"unknown namespace", "other-12", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, global := range []bool{false, true} {
				rpc := &legacyTestRPC{}
				client := &LegacyClient{clientV1: rpc, tracer: noop.Tracer{}}
				req := legacyRequest()
				req.Namespace, req.GlobalOrg = tc.namespace, global
				_, err := client.LegacyGetUserPermissions(t.Context(), legacyCaller("*", "authz.grafana.app/legacyuserpermissions:get"), req)
				if !tc.valid {
					require.ErrorIs(t, err, ErrInvalidLegacyUserPermissionsRequest)
					require.Zero(t, rpc.calls)
					continue
				}
				require.NoError(t, err)
				require.Equal(t, tc.namespace, rpc.request.Namespace)
				encoded, err := proto.Marshal(rpc.request)
				require.NoError(t, err)
				decoded := &authzv1.LegacyGetUserPermissionsRequest{}
				require.NoError(t, proto.Unmarshal(encoded, decoded))
				require.Equal(t, global, decoded.GetGlobalOrg())
			}
		})
	}
}

func TestClient_LegacyGetUserPermissionsGlobalOrgDoesNotBypassNamespace(t *testing.T) {
	rpc := &legacyTestRPC{}
	client := &LegacyClient{clientV1: rpc, tracer: noop.Tracer{}}
	req := legacyRequest()
	req.GlobalOrg = true
	got, err := client.LegacyGetUserPermissions(t.Context(), legacyCaller("stacks-13", "authz.grafana.app/legacyuserpermissions:get"), req)
	require.ErrorIs(t, err, ErrNamespaceMismatch)
	require.Empty(t, got.Permissions)
	require.Zero(t, rpc.calls)
}

func TestClient_LegacyGetUserPermissionsPreservesIdentityAssertions(t *testing.T) {
	zero, negative := int64(0), int64(-1)
	for _, tc := range []struct {
		name     string
		identity types.LegacyPermissionIdentity
	}{
		{"numeric UID", legacyRequest().Identity},
		{"service account", types.LegacyPermissionIdentity{Type: types.TypeServiceAccount, UID: "sa", HasUniqueID: true}},
		{"anonymous absent ID", types.LegacyPermissionIdentity{Type: types.TypeAnonymous, OrgRole: "Viewer"}},
		{"anonymous zero ID", types.LegacyPermissionIdentity{Type: types.TypeAnonymous, InternalID: &zero, OrgRole: "None"}},
		{"renderer", types.LegacyPermissionIdentity{Type: types.TypeRenderService}},
		{"API key", types.LegacyPermissionIdentity{Type: types.TypeAPIKey, UID: "key", HasUniqueID: true}},
		{"no unique ID", types.LegacyPermissionIdentity{}},
		{"legacy negative ID", types.LegacyPermissionIdentity{InternalID: &negative}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := &legacyTestRPC{}
			client := &LegacyClient{clientV1: rpc, tracer: noop.Tracer{}}
			req := legacyRequest()
			req.Identity = tc.identity
			_, err := client.LegacyGetUserPermissions(t.Context(), legacyGroupedCaller{legacyCaller("stacks-12", "authz.grafana.app/legacyuserpermissions:get")}, req)
			require.NoError(t, err)
			// Exercise scalar presence through protobuf encoding, not only Go pointers.
			encoded, err := proto.Marshal(rpc.request)
			require.NoError(t, err)
			decoded := &authzv1.LegacyGetUserPermissionsRequest{}
			require.NoError(t, proto.Unmarshal(encoded, decoded))
			i := decoded.Identity
			require.Equal(t, string(tc.identity.Type), i.Type)
			require.Equal(t, tc.identity.UID, i.Uid)
			require.Equal(t, tc.identity.InternalID, i.InternalId)
			require.Equal(t, tc.identity.HasUniqueID, i.HasUniqueId)
			require.Equal(t, tc.identity.OrgRole, i.OrgRole)
			require.Equal(t, tc.identity.IsGrafanaAdmin, i.IsGrafanaAdmin)
			require.Equal(t, tc.identity.TeamIDs, i.TeamIds)
			require.Equal(t, tc.identity.Groups, i.Groups, "never substitute the caller's groups")
		})
	}
}

type legacyGroupedCaller struct{ types.AuthInfo }

func (legacyGroupedCaller) GetGroups() []string { return []string{"caller-group"} }

type legacyDelegatedCaller struct{ types.AuthInfo }

func (legacyDelegatedCaller) GetIdentityType() types.IdentityType { return types.TypeUser }
func (legacyDelegatedCaller) GetTokenDelegatedPermissions() []string {
	return []string{"authz.grafana.app/legacyuserpermissions:get"}
}
