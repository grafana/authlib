package authz

import (
	"context"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grafana/authlib/claims"
)

const (
	DefaultStackIDMetadataKey = "X-Stack-ID"
)

var (
	ErrorMissingMetadata              = status.Errorf(codes.Unauthenticated, "unauthenticated: missing metadata")
	ErrorMissingCallerInfo            = status.Errorf(codes.Unauthenticated, "unauthenticated: missing caller auth info")
	ErrorInvalidStackID               = status.Errorf(codes.Unauthenticated, "unauthenticated: invalid stack ID")
	ErrorMissingIDToken               = status.Errorf(codes.Unauthenticated, "unauthenticated: missing id token")
	ErrorMissingAccessToken           = status.Errorf(codes.Unauthenticated, "unauthenticated: missing access token")
	ErrorIDTokenNamespaceMismatch     = status.Errorf(codes.PermissionDenied, "unauthorized: id token namespace does not match expected namespace")
	ErrorAccessTokenNamespaceMismatch = status.Errorf(codes.PermissionDenied, "unauthorized: access token namespace does not match expected namespace")
)

type NamespaceAccessCheckerOverride interface {
	CheckAccessByIdOverride(ctx context.Context) error
}

type NamespaceAccessChecker interface {
	CheckAccess(caller claims.AuthInfo, namespace string) error
	CheckAccessByID(caller claims.AuthInfo, id int64) error
}

var _ NamespaceAccessChecker = &NamespaceAccessCheckerImpl{}

type NamespaceAccessCheckerOption func(*NamespaceAccessCheckerImpl)

type NamespaceAccessCheckerImpl struct {
	// namespaceFmt is the namespace formatter used to generate the expected namespace.
	// Ex: "stacks-%d" -> "stacks-12"
	namespaceFmt claims.NamespaceFormatter

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
func NewNamespaceAccessChecker(namespaceFmt claims.NamespaceFormatter, opts ...NamespaceAccessCheckerOption) *NamespaceAccessCheckerImpl {
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

func (na *NamespaceAccessCheckerImpl) CheckAccess(caller claims.AuthInfo, expectedNamespace string) error {
	if na.idTokenEnabled {
		idClaims := caller.GetIdentity()
		if idClaims == nil || idClaims.IsNil() {
			if na.idTokenRequired {
				return ErrorMissingIDToken
			}
			// for else-if branch below,
			// when id token claims are evaluated with an access token claims (with wildcard namespace) present
			// but expectedNamespace is *, we skip the namespace equality check since it will always fail
		} else if expectedNamespace != "*" && !claims.NamespaceMatches(idClaims, expectedNamespace) {
			return ErrorIDTokenNamespaceMismatch
		}
	}
	if na.accessTokenEnabled {
		accessClaims := caller.GetAccess()
		if accessClaims == nil || accessClaims.IsNil() {
			return ErrorMissingAccessToken
		}
		// for if branch below,
		// when access token claims with a wildcard namespace are passed in, we skip the namespace equality check
		// it **will fail** when checking on resources in specific namespaces, which we don't want
		if !claims.NamespaceMatches(accessClaims, expectedNamespace) {
			return ErrorAccessTokenNamespaceMismatch
		}
	}
	return nil
}

// CheckAccessById uses the specified identifier to use with the namespace formatter
// to generate the expected namespace which will be checked for access.
func (na *NamespaceAccessCheckerImpl) CheckAccessByID(caller claims.AuthInfo, id int64) error {
	expectedNamespace := na.namespaceFmt(id)
	return na.CheckAccess(caller, expectedNamespace)
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
		if overrideSrv, ok := info.Server.(NamespaceAccessCheckerOverride); ok {
			err := overrideSrv.CheckAccessByIdOverride(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			caller, ok := claims.From(ctx)
			if !ok {
				return nil, ErrMissingCaller
			}

			stackID, err := stackID(ctx)
			if err != nil {
				return nil, err
			}

			err = na.CheckAccessByID(caller, stackID)
			if err != nil {
				return nil, err
			}
		}
		return handler(ctx, req)
	}
}

// gRPC Stream Interceptor for namespace validation
func StreamNamespaceAccessInterceptor(na NamespaceAccessChecker, stackID StackIDExtractors) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()
		if overrideSrv, ok := srv.(NamespaceAccessCheckerOverride); ok {
			err := overrideSrv.CheckAccessByIdOverride(ctx)
			if err != nil {
				return err
			}
		} else {
			caller, ok := claims.From(ctx)
			if !ok {
				return ErrMissingCaller
			}

			stackID, err := stackID(ctx)
			if err != nil {
				return err
			}

			err = na.CheckAccessByID(caller, stackID)
			if err != nil {
				return err
			}
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
