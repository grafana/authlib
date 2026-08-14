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

func TestGetUserPermissionsResponseDefinesCacheUntil(t *testing.T) {
	field := (&GetUserPermissionsResponse{}).ProtoReflect().Descriptor().Fields().ByNumber(2)
	require.NotNil(t, field)
	require.Equal(t, protoreflect.Name("cache_until"), field.Name())
	require.Equal(t, "cacheUntil", field.JSONName())
}
