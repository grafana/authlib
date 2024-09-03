package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type serviceWithOverride struct {
	called bool
	expErr error
}

func (s *serviceWithOverride) AuthorizeFuncOverride(ctx context.Context) error {
	s.called = true
	return s.expErr
}

func TestUnaryAuthorizeInterceptor(t *testing.T) {
	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return nil, nil
	}

	accessCalled := false
	var expectedErr error
	accessFunc := func(ctx context.Context) error {
		accessCalled = true
		return expectedErr
	}

	interceptor := UnaryAuthorizeInterceptor(accessFunc)
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)
	require.True(t, handlerCalled)
	require.True(t, accessCalled)

	accessCalled = false
	handlerCalled = false
	srv := &serviceWithOverride{}
	_, err = interceptor(context.Background(), nil, &grpc.UnaryServerInfo{Server: srv}, handler)
	require.NoError(t, err)
	require.True(t, handlerCalled)
	require.False(t, accessCalled)
	require.True(t, srv.called)

	accessCalled = false
	handlerCalled = false
	expectedErr = ErrInvalidQuery
	_, err = interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
	require.Error(t, err)
	require.False(t, handlerCalled)
	require.True(t, accessCalled)

	accessCalled = false
	handlerCalled = false
	srv = &serviceWithOverride{expErr: ErrInvalidQuery}
	_, err = interceptor(context.Background(), nil, &grpc.UnaryServerInfo{Server: srv}, handler)
	require.Error(t, err)
	require.False(t, handlerCalled)
	require.False(t, accessCalled)
	require.True(t, srv.called)
}
