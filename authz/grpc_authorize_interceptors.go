package authz

import (
	"context"

	"google.golang.org/grpc"
)

// AuthorizeFunc is the pluggable function that performs access control checks.
//
// The passed in `Context` will contain previous context values, such as grpc metadata
// or even the caller's claims if the grpc_authenticator interceptor is used before the access interceptor.
// The function should return an error if the caller does not have access.
//
// If error is returned, its `grpc.Code()` will be returned to the user as well as the verbatim message.
// Please make sure you use `codes.PermissionDenied` (lacking perms) appropriately.
type AuthorizeFunc func(ctx context.Context) error

// ServiceAuthorizeFuncOverride allows a given gRPC service implementation to override the global `AuthorizeFunc`.
//
// If a service implements the AuthorizeFuncOverride method, it takes precedence over the `AuthorizeFunc` method,
// and will be called instead of AuthorizeFunc for all method invocations within that service.
type ServiceAuthorizeFuncOverride interface {
	AuthorizeFuncOverride(ctx context.Context) error
}

// UnaryAuthorizeInterceptor returns a new unary server interceptor that performs per-request authorization.
func UnaryAuthorizeInterceptor(accessFunc AuthorizeFunc) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if overrideSrv, ok := info.Server.(ServiceAuthorizeFuncOverride); ok {
			err := overrideSrv.AuthorizeFuncOverride(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			err := accessFunc(ctx)
			if err != nil {
				return nil, err
			}
		}
		return handler(ctx, req)
	}
}

// StreamAuthorizeInterceptor returns a new stream server interceptor that performs per-request authorization.
func StreamAuthorizeInterceptor(accessFunc AuthorizeFunc) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()
		if overrideSrv, ok := srv.(ServiceAuthorizeFuncOverride); ok {
			err := overrideSrv.AuthorizeFuncOverride(ctx)
			if err != nil {
				return err
			}
		} else {
			err := accessFunc(ctx)
			if err != nil {
				return err
			}
		}
		return handler(srv, stream)
	}
}
