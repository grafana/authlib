package authz

import (
	"context"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grafana/authlib/authn"
)

const (
	DefaultStackIDMetadataKey = "X-Stack-ID"
)

var (
	ErrorMissingMetadata              = status.Errorf(codes.Unauthenticated, "unauthenticated: missing metadata")
	ErrorMissingCallerInfo            = status.Errorf(codes.Unauthenticated, "unauthenticated: missing caller auth info")
	ErrorInvalidStackID               = status.Errorf(codes.Unauthenticated, "unauthenticated: invalid stack ID")
	ErrorMissingIDToken               = status.Errorf(codes.Unauthenticated, "unauthenticated: missing id token")
	ErrorIDTokenNamespaceMismatch     = status.Errorf(codes.PermissionDenied, "unauthorized: id token namespace does not match expected namespace")
	ErrorAccessTokenNamespaceMismatch = status.Errorf(codes.PermissionDenied, "unauthorized: access token namespace does not match expected namespace")
)

type NamespaceAccessChecker interface {
	CheckAccess(caller authn.CallerAuthInfo, stackID int64) error
}

type NamespaceAccessCheckerOption func(*NamespaceAccessCheckerImpl)

type NamespaceAccessCheckerImpl struct {
	// namespaceFmt is the namespace formatter used to generate the expected namespace.
	// Ex: "stack-%d" -> "stack-12"
	namespaceFmt authn.NamespaceFormatter

	// idTokenEnabled is a flag to enable ID token namespace validation.
	idTokenEnabled bool
	// idTokenRequired is a flag to require the ID token for namespace validation.
	// if the ID is not provided and required is true, an error is returned.
	idTokenRequired bool
	// accessTokenEnabled is a flag to enable access token namespace validation.
	accessTokenEnabled bool
}

// WithIDTokenNamespaceAuthorizerOption enables ID token namespace validation.
// If required is true, the ID token is required for validation.
func WithIDTokenNamespaceAccessCheckerOption(required bool) NamespaceAccessCheckerOption {
	return func(na *NamespaceAccessCheckerImpl) {
		na.idTokenEnabled = true
		na.idTokenRequired = required
	}
}

// WithDisableAccessTokenNamespaceAuthorizerOption disables access token namespace validation.
func WithDisableAccessTokenNamespaceAccessCheckerOption() NamespaceAccessCheckerOption {
	return func(na *NamespaceAccessCheckerImpl) {
		na.accessTokenEnabled = false
	}
}

// NewNamespaceAuthorizer creates a new namespace authorizer.
// If both ID token and access token are disabled, the authorizer will always return nil.
func NewNamespaceAccessChecker(namespaceFmt authn.NamespaceFormatter, opts ...NamespaceAccessCheckerOption) *NamespaceAccessCheckerImpl {
	na := &NamespaceAccessCheckerImpl{
		namespaceFmt:       namespaceFmt,
		idTokenEnabled:     false,
		idTokenRequired:    false,
		accessTokenEnabled: true,
	}

	for _, opt := range opts {
		opt(na)
	}

	return na
}

func (na *NamespaceAccessCheckerImpl) CheckAccess(caller authn.CallerAuthInfo, stackID int64) error {
	expectedNamespace := na.namespaceFmt(stackID)
	if na.idTokenEnabled {
		if caller.IDTokenClaims == nil {
			if na.idTokenRequired {
				return ErrorMissingIDToken
			}
		} else if caller.IDTokenClaims.Rest.Namespace != expectedNamespace {
			return ErrorIDTokenNamespaceMismatch
		}
	}
	if na.accessTokenEnabled && !caller.AccessTokenClaims.Rest.NamespaceMatches(expectedNamespace) {
		return ErrorAccessTokenNamespaceMismatch
	}
	return nil
}

type StackIDExtractors func(context.Context) (int64, error)

// MetadataStackIDExtractor extracts the stack ID from the gRPC metadata.
func MetadataStackIDExtractor(key string) StackIDExtractors {
	return func(ctx context.Context) (int64, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return 0, ErrorMissingMetadata
		}
		stackIDStr, ok := getFirstMetadataValue(md, key)
		if !ok {
			return 0, ErrorMissingMetadata
		}

		stackID, err := strconv.ParseInt(stackIDStr, 10, 64)
		if err != nil {
			return 0, ErrorInvalidStackID
		}

		return stackID, nil
	}
}

// gRPC Unary Interceptor for namespace validation
func UnaryNamespaceAccessInterceptor(na NamespaceAccessChecker, stackID StackIDExtractors) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		caller, ok := authn.GetCallerAuthInfoFromContext(ctx)
		if !ok {
			return nil, ErrMissingCaller
		}

		stackID, err := stackID(ctx)
		if err != nil {
			return nil, err
		}

		err = na.CheckAccess(caller, stackID)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// gRPC Stream Interceptor for namespace validation
func StreamNamespaceAccessInterceptor(na NamespaceAccessChecker, stackID StackIDExtractors) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()

		caller, ok := authn.GetCallerAuthInfoFromContext(ctx)
		if !ok {
			return ErrMissingCaller
		}

		stackID, err := stackID(ctx)
		if err != nil {
			return err
		}

		err = na.CheckAccess(caller, stackID)
		if err != nil {
			return err
		}

		return handler(srv, stream)
	}
}

func getFirstMetadataValue(md metadata.MD, key string) (string, bool) {
	values := md.Get(key)
	if len(values) == 0 {
		return "", false
	}
	if len(values[0]) == 0 {
		return "", false
	}

	return values[0], true
}
