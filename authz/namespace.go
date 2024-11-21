package authz

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grafana/authlib/claims"
)

const (
	DefaultStackIDMetadataKey   = "X-Stack-ID"
	DefaultNamespaceMetadataKey = "X-Namespace"
)

var (
	ErrorMissingMetadata              = status.Errorf(codes.Unauthenticated, "unauthenticated: missing metadata")
	ErrorInvalidStackID               = status.Errorf(codes.Unauthenticated, "unauthenticated: invalid stack ID")
	ErrorMissingIDToken               = status.Errorf(codes.Unauthenticated, "unauthenticated: missing id token")
	ErrorMissingAccessToken           = status.Errorf(codes.Unauthenticated, "unauthenticated: missing access token")
	ErrorIDTokenNamespaceMismatch     = status.Errorf(codes.PermissionDenied, "unauthorized: id token namespace does not match expected namespace")
	ErrorAccessTokenNamespaceMismatch = status.Errorf(codes.PermissionDenied, "unauthorized: access token namespace does not match expected namespace")
)

type NamespaceAccessChecker interface {
	CheckAccess(ctx context.Context, caller claims.AuthInfo, namespace string) error
}

var _ NamespaceAccessChecker = &NamespaceAccessCheckerImpl{}

type NamespaceAccessCheckerOption func(*NamespaceAccessCheckerImpl)

type NamespaceAccessCheckerImpl struct {
	tracer trace.Tracer
}

func WithTracerAccessCheckerOption(tracer trace.Tracer) NamespaceAccessCheckerOption {
	return func(na *NamespaceAccessCheckerImpl) {
		na.tracer = tracer
	}
}

// NewNamespaceAuthorizer creates a new namespace authorizer.
func NewNamespaceAccessChecker(opts ...NamespaceAccessCheckerOption) *NamespaceAccessCheckerImpl {
	na := &NamespaceAccessCheckerImpl{}

	for _, opt := range opts {
		opt(na)
	}

	if na.tracer == nil {
		na.tracer = noop.Tracer{}
	}

	return na
}

func (na *NamespaceAccessCheckerImpl) CheckAccess(ctx context.Context, caller claims.AuthInfo, expectedNamespace string) error {
	_, span := na.tracer.Start(ctx, "NamespaceAccessChecker.CheckAccess")
	defer span.End()
	span.SetAttributes(attribute.String("expectedNamespace", expectedNamespace))

	if expectedNamespace != "*" && !claims.NamespaceMatches(caller.GetNamespace(), expectedNamespace) {
		span.RecordError(ErrorIDTokenNamespaceMismatch)
		return ErrorIDTokenNamespaceMismatch

	}

	return nil
}

type NamespaceExtractor func(context.Context) (string, error)

// MetadataStackIDExtractor extracts the stack ID from the gRPC metadata.
func MetadataNamespaceExtractor(key string) NamespaceExtractor {
	return func(ctx context.Context) (string, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return "", ErrorMissingMetadata
		}
		namespace, ok := getFirstMetadataValue(md, key)
		if !ok {
			return "", ErrorMissingMetadata
		}

		return namespace, nil
	}
}

// NamespaceAuthorizationFunc returns a AuthorizeFunc that checks the caller claims access to a given namespace.
// This function can be used with UnaryAuthorizeInterceptor and StreamAuthorizeInterceptor.
func NamespaceAuthorizationFunc(na NamespaceAccessChecker, nsExtract NamespaceExtractor) AuthorizeFunc {
	return func(ctx context.Context) error {
		caller, ok := claims.From(ctx)
		if !ok {
			return ErrMissingCaller
		}

		namespace, err := nsExtract(ctx)
		if err != nil {
			return err
		}

		return na.CheckAccess(ctx, caller, namespace)
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
