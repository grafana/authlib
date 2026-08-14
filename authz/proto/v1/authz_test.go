package authzv1

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestAuthzServiceDefinesGetUserPermissions(t *testing.T) {
	service := File_proto_v1_authz_proto.Services().ByName(protoreflect.Name("AuthzService"))
	require.NotNil(t, service)

	method := service.Methods().ByName(protoreflect.Name("GetUserPermissions"))
	require.NotNil(t, method)
	require.True(t, method.IsStreamingServer())
	require.False(t, method.IsStreamingClient())
}
