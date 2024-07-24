package authn

import (
	"context"
	"fmt"
	"strings"

	"github.com/gogo/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

var (
	ErrorMissingMetadata    = status.Error(codes.Unauthenticated, "unauthenticated: no metadata found")
	ErrorMissingIDToken     = status.Error(codes.Unauthenticated, "unauthenticated: missing id token")
	ErrorMissingAccessToken = status.Error(codes.Unauthenticated, "unauthenticated: missing access token")
	ErrorInvalidIDToken     = status.Error(codes.PermissionDenied, "unauthorized: invalid id token")
	ErrorInvalidAccessToken = status.Error(codes.PermissionDenied, "unauthorized: invalid access token")
)

// GrpcAuthenticatorConfig holds the configuration for the gRPC authenticator.
type GrpcAuthenticatorConfig struct {
}

// GrpcAuthenticator is a gRPC authenticator that authenticates incoming requests based on the access token and ID token.
type GrpcAuthenticator struct {
	atVerifier   Verifier[AccessTokenClaims]
	idVerifier   Verifier[IDTokenClaims]
	namespaceFmt NamespaceFormatter
}

func (ga *GrpcAuthenticator) Authenticate(ctx context.Context) (context.Context, error) {
	callerInfo := CallerAuthInfo{}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrorMissingMetadata
	}

	at, ok := getFirstMetadataValue(md, DefaultAccessTokenMetadataKey)
	if !ok {
		return nil, ErrorMissingAccessToken
	}

	atClaims, err := ga.atVerifier.Verify(ctx, at)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, ErrorInvalidAccessToken)
	}

	callerInfo.AccessTokenClaims = *atClaims

	return AddCallerAuthInfoToContext(ctx, callerInfo), nil
}

func (ga *GrpcAuthenticator) authenticateService(stackID int64, claims *Claims[AccessTokenClaims]) error {
	expectedNamespace := ga.namespaceFmt(stackID)

	// Allow access tokens with that has a wildcard namespace or a namespace matching this instance.
	if !claims.Rest.NamespaceMatches(expectedNamespace) {
		return fmt.Errorf("unexpected access token namespace: %s", claims.Rest.Namespace, ErrorInvalidAccessToken)
	}

	subject, err := parseSubject(claims.Subject)
	if err != nil {
		return fmt.Errorf("failed to parse access token subject %v", err, ErrorInvalidAccessToken)
	}

	if subject.namespace == namespaceAccessPolicy {
		return fmt.Errorf("access token subject '%s' namespace is not allowed: %w", subject.namespace, ErrorInvalidAccessToken)
	}

	return nil
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

// ------
// Subject
// FIXME: This is a duplicate of Grafana's identity namespaces and namespacedID. It should be moved to a shared package.
// ------
const (
	namespaceUser           subjectNamespace = "user"
	namespaceAPIKey         subjectNamespace = "api-key"
	namespaceServiceAccount subjectNamespace = "service-account"
	namespaceAnonymous      subjectNamespace = "anonymous"
	namespaceRenderService  subjectNamespace = "render"
	namespaceAccessPolicy   subjectNamespace = "access-policy"
	namespaceProvisioning   subjectNamespace = "provisioning"
	namespaceEmpty          subjectNamespace = ""
)

var (
	ErrorInvalidSubject   = status.Error(codes.PermissionDenied, "unauthorized: invalid subject")
	ErrorInvalidNamespace = status.Error(codes.PermissionDenied, "unauthorized: invalid namespace")
)

type subjectNamespace string

func (n subjectNamespace) isValid() error {
	switch n {
	case namespaceUser, namespaceAPIKey, namespaceServiceAccount, namespaceAnonymous, namespaceRenderService, namespaceAccessPolicy, namespaceProvisioning, namespaceEmpty:
		return nil
	default:
		return fmt.Errorf("invalid namespace %s: %w", n, ErrorInvalidNamespace)
	}
}

type subject struct {
	id        string           // Ex: 1234567890
	namespace subjectNamespace // Ex: user, service-account, api-key
}

func parseSubject(str string) (subject, error) {
	var subject subject

	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return subject, fmt.Errorf("expected namespace id to have 2 parts: %w", ErrorInvalidSubject)
	}

	subject.id = parts[1]
	subject.namespace = subjectNamespace(parts[0])

	err := subject.namespace.isValid()
	if err != nil {
		return subject, err
	}

	return subject, nil
}
