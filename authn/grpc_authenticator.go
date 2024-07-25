package authn

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	ErrorMissingMetadata    = status.Error(codes.Unauthenticated, "unauthenticated: no metadata found")
	ErrorMissingIDToken     = status.Error(codes.Unauthenticated, "unauthenticated: missing id token")
	ErrorMissingAccessToken = status.Error(codes.Unauthenticated, "unauthenticated: missing access token")
	ErrorInvalidStackID     = status.Error(codes.PermissionDenied, "unauthorized: invalid stack ID")
	ErrorInvalidIDToken     = status.Error(codes.PermissionDenied, "unauthorized: invalid id token")
	ErrorInvalidAccessToken = status.Error(codes.PermissionDenied, "unauthorized: invalid access token")
)

// TODO (gamab) - Constructor
// TODO (gamab) - ID token should be optional
// TODO (gamab) - Add unsafe option to make access tokens optional as well (on-prem support)
// TODO (gamab) - Metadata key should be configurable
// TODO (gamab) - StackID extract should be configurable - could come from the metadata, path, id token.

// GrpcAuthenticatorConfig holds the configuration for the gRPC authenticator.
type GrpcAuthenticatorConfig struct {
}

// GrpcAuthenticator is a gRPC authenticator that authenticates incoming requests based on the access token and ID token.
type GrpcAuthenticator struct {
	atVerifier   Verifier[AccessTokenClaims]
	idVerifier   Verifier[IDTokenClaims]
	namespaceFmt NamespaceFormatter
}

// Authenticate authenticates the incoming request based on the access token and ID token, and returns the context with the caller information.
func (ga *GrpcAuthenticator) Authenticate(ctx context.Context) (context.Context, error) {
	callerInfo := CallerAuthInfo{}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrorMissingMetadata
	}

	// TODO (gamab) - StackID extract should be configurable - could come from the metadata, path, id token.
	stackID, ok := getFirstMetadataValue(md, DefaultStackIDMetadataKey)
	if !ok {
		return nil, fmt.Errorf("missing stack ID: %w", ErrorMissingMetadata)
	}
	stackIDInt, err := strconv.ParseInt(stackID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stack ID: %w", ErrorInvalidStackID)
	}
	callerInfo.StackID = stackIDInt

	atClaims, err := ga.authenticateService(ctx, stackIDInt, md)
	if err != nil {
		return nil, err
	}
	callerInfo.AccessTokenClaims = *atClaims

	idClaims, err := ga.authenticateUser(ctx, stackIDInt, md)
	if err != nil {
		// TODO (gamab): Handle id token optionality
		return nil, err
	}
	callerInfo.IDTokenClaims = idClaims

	return AddCallerAuthInfoToContext(ctx, callerInfo), nil
}

func (ga *GrpcAuthenticator) authenticateService(ctx context.Context, stackID int64, md metadata.MD) (*Claims[AccessTokenClaims], error) {
	at, ok := getFirstMetadataValue(md, DefaultAccessTokenMetadataKey)
	if !ok {
		return nil, ErrorMissingAccessToken
	}

	claims, err := ga.atVerifier.Verify(ctx, at)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, ErrorInvalidAccessToken)
	}

	expectedNamespace := ga.namespaceFmt(stackID)

	// Allow access tokens with that has a wildcard namespace or a namespace matching this instance.
	if !claims.Rest.NamespaceMatches(expectedNamespace) {
		return nil, fmt.Errorf("unexpected access token namespace '%s': %w", claims.Rest.Namespace, ErrorInvalidAccessToken)
	}

	subject, err := parseSubject(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token subject - %v: %w", err, ErrorInvalidAccessToken)
	}

	if subject.Type != typeAccessPolicy {
		return nil, fmt.Errorf("access token subject '%s' namespace is not allowed: %w", subject.Type, ErrorInvalidAccessToken)
	}

	return claims, nil
}

func (ga *GrpcAuthenticator) authenticateUser(ctx context.Context, stackID int64, md metadata.MD) (*Claims[IDTokenClaims], error) {
	id, ok := getFirstMetadataValue(md, DefaultIdTokenMetadataKey)
	if !ok {
		return nil, ErrorMissingIDToken
	}

	claims, err := ga.idVerifier.Verify(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, ErrorInvalidIDToken)
	}

	expectedNamespace := ga.namespaceFmt(stackID)

	if claims.Rest.Namespace != expectedNamespace {
		return nil, fmt.Errorf("unexpected id token namespace '%s': %w", claims.Rest.Namespace, ErrorInvalidIDToken)
	}

	subject, err := parseSubject(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id token subject - %v: %w", err, ErrorInvalidIDToken)
	}

	if subject.Type != typeUser && subject.Type != typeServiceAccount {
		return nil, fmt.Errorf("id token subject '%s' namespace is not allowed: %w", subject.Type, ErrorInvalidIDToken)
	}

	return claims, nil
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
	typeUser           subjectType = "user"
	typeAPIKey         subjectType = "api-key"
	typeServiceAccount subjectType = "service-account"
	typeAnonymous      subjectType = "anonymous"
	typeRenderService  subjectType = "render"
	typeAccessPolicy   subjectType = "access-policy"
	typeProvisioning   subjectType = "provisioning"
	typeEmpty          subjectType = ""
)

var (
	ErrorInvalidSubject   = status.Error(codes.PermissionDenied, "unauthorized: invalid subject")
	ErrorInvalidNamespace = status.Error(codes.PermissionDenied, "unauthorized: invalid namespace")
)

type subjectType string

func (n subjectType) isValid() error {
	switch n {
	case typeUser, typeAPIKey, typeServiceAccount, typeAnonymous, typeRenderService, typeAccessPolicy, typeProvisioning, typeEmpty:
		return nil
	default:
		return fmt.Errorf("invalid namespace %s: %w", n, ErrorInvalidNamespace)
	}
}

type subject struct {
	ID   string      // Ex: 1234567890
	Type subjectType // Ex: user, service-account, api-key
}

func parseSubject(str string) (subject, error) {
	var subject subject

	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return subject, fmt.Errorf("expected namespace id to have 2 parts: %w", ErrorInvalidSubject)
	}

	subject.ID = parts[1]
	subject.Type = subjectType(parts[0])

	err := subject.Type.isValid()
	if err != nil {
		return subject, err
	}

	return subject, nil
}
