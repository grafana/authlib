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

// TODO (gamab) - StackID extract should be configurable - could come from the metadata, path, id token.

// GrpcAuthenticatorOptions
type GrpcAuthenticatorOption func(*GrpcAuthenticator)

// GrpcAuthenticatorConfig holds the configuration for the gRPC authenticator.
type GrpcAuthenticatorConfig struct {
	// AccessTokenMetadataKey is the key used to retrieve the access token from the incoming metadata.
	// Defaults to "X-Access-Token".
	AccessTokenMetadataKey string
	// IDTokenMetadataKey is the key used to retrieve the ID token from the incoming metadata.
	// Defaults to "X-Id-Token".
	IDTokenMetadataKey string
	// StackIDMetadataKey is the key used to retrieve the stack ID from the incoming metadata.
	// Defaults to "X-Stack-Id".
	StackIDMetadataKey string

	// KeyRetrieverConfig holds the configuration for the key retriever.
	// Ignored if KeyRetrieverOption is provided.
	KeyRetrieverConfig KeyRetrieverConfig
	// VerifierConfig holds the configuration for the token verifiers.
	VerifierConfig VerifierConfig

	// accessTokenAuthEnabled is a flag to enable access token authentication.
	// If disabled, only ID token authentication is performed. Defaults to true.
	accessTokenAuthEnabled bool
	// idTokenAuthEnabled is a flag to enable ID token authentication.
	// If disabled, only access token authentication is performed.
	idTokenAuthEnabled bool
	// idTokenAuthRequired is a flag to require the ID token for authentication.
	// If required is false, the ID token is optional for authentication
	idTokenAuthRequired bool
}

// GrpcAuthenticator is a gRPC authenticator that authenticates incoming requests based on the access token and ID token.
type GrpcAuthenticator struct {
	cfg          *GrpcAuthenticatorConfig
	keyRetriever KeyRetriever
	atVerifier   Verifier[AccessTokenClaims]
	idVerifier   Verifier[IDTokenClaims]
	namespaceFmt NamespaceFormatter
}

func WithKeyRetrieverOption(kr KeyRetriever) GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticator) {
		ga.keyRetriever = kr
	}
}

// WithIDTokenAuthOption is a flag to enable ID token authentication.
// If required is true, the ID token is required for authentication.
func WithIDTokenAuthOption(required bool) GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticator) {
		ga.cfg.idTokenAuthEnabled = true
		ga.cfg.idTokenAuthRequired = required
	}
}

// WithDisableAccessTokenAuthOption is an option to disable access token authentication.
// Warning: Using this option means there won't be any service authentication.
func WithDisableAccessTokenAuthOption() GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticator) {
		ga.cfg.accessTokenAuthEnabled = false
	}
}

func setGrpcAuthenticatorCfgDefaults(cfg *GrpcAuthenticatorConfig) {
	if cfg.AccessTokenMetadataKey == "" {
		cfg.AccessTokenMetadataKey = DefaultAccessTokenMetadataKey
	}
	if cfg.IDTokenMetadataKey == "" {
		cfg.IDTokenMetadataKey = DefaultIdTokenMetadataKey
	}
	if cfg.StackIDMetadataKey == "" {
		cfg.StackIDMetadataKey = DefaultStackIDMetadataKey
	}
	cfg.accessTokenAuthEnabled = true
}

func NewGrpcAuthenticator(cfg *GrpcAuthenticatorConfig, opts ...GrpcAuthenticatorOption) (*GrpcAuthenticator, error) {
	setGrpcAuthenticatorCfgDefaults(cfg)

	ga := &GrpcAuthenticator{cfg: cfg}
	for _, opt := range opts {
		opt(ga)
	}

	if ga.keyRetriever == nil && (ga.cfg.accessTokenAuthEnabled || ga.cfg.idTokenAuthEnabled) {
		if cfg.KeyRetrieverConfig.SigningKeysURL == "" {
			return nil, fmt.Errorf("missing signing keys URL: %w", ErrMissingConfig)
		}

		kr := NewKeyRetriever(cfg.KeyRetrieverConfig)
		ga.keyRetriever = kr
	}

	if ga.cfg.accessTokenAuthEnabled {
		ga.atVerifier = NewAccessTokenVerifier(cfg.VerifierConfig, ga.keyRetriever)
	}

	if ga.cfg.idTokenAuthEnabled {
		ga.idVerifier = NewIDTokenVerifier(cfg.VerifierConfig, ga.keyRetriever)
	}

	return ga, nil
}

// Authenticate authenticates the incoming request based on the access token and ID token, and returns the context with the caller information.
func (ga *GrpcAuthenticator) Authenticate(ctx context.Context) (context.Context, error) {
	callerInfo := CallerAuthInfo{}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrorMissingMetadata
	}

	stackID, ok := getFirstMetadataValue(md, ga.cfg.StackIDMetadataKey)
	if !ok {
		return nil, fmt.Errorf("missing stack ID: %w", ErrorMissingMetadata)
	}
	stackIDInt, err := strconv.ParseInt(stackID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stack ID: %w", ErrorInvalidStackID)
	}
	callerInfo.StackID = stackIDInt

	if ga.cfg.accessTokenAuthEnabled {
		atClaims, err := ga.authenticateService(ctx, stackIDInt, md)
		if err != nil {
			return nil, err
		}
		callerInfo.AccessTokenClaims = *atClaims
	}

	if ga.cfg.idTokenAuthEnabled {
		idClaims, err := ga.authenticateUser(ctx, stackIDInt, md)
		if err != nil {
			return nil, err
		}
		callerInfo.IDTokenClaims = idClaims
	}

	return AddCallerAuthInfoToContext(ctx, callerInfo), nil
}

func (ga *GrpcAuthenticator) authenticateService(ctx context.Context, stackID int64, md metadata.MD) (*Claims[AccessTokenClaims], error) {
	at, ok := getFirstMetadataValue(md, ga.cfg.AccessTokenMetadataKey)
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
		return nil, fmt.Errorf("access token subject '%s' is not valid: %w", claims.Subject, err)
	}

	if subject.Type != typeAccessPolicy {
		return nil, fmt.Errorf("access token subject '%s' type is not allowed: %w", subject.Type, ErrorInvalidSubjectType)
	}

	return claims, nil
}

func (ga *GrpcAuthenticator) authenticateUser(ctx context.Context, stackID int64, md metadata.MD) (*Claims[IDTokenClaims], error) {
	id, ok := getFirstMetadataValue(md, ga.cfg.IDTokenMetadataKey)
	if !ok {
		if ga.cfg.idTokenAuthRequired {
			return nil, ErrorMissingIDToken
		}
		return nil, nil
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
		return nil, fmt.Errorf("id token subject '%s' is not valid: %w", claims.Subject, err)
	}

	if subject.Type != typeUser && subject.Type != typeServiceAccount {
		return nil, fmt.Errorf("id token subject '%s' type is not allowed: %w", subject.Type, ErrorInvalidSubjectType)
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
	ErrorInvalidSubject     = status.Error(codes.PermissionDenied, "unauthorized: invalid subject")
	ErrorInvalidSubjectType = status.Error(codes.PermissionDenied, "unauthorized: invalid subject type")
)

type subjectType string

func (n subjectType) isValid() error {
	switch n {
	case typeUser, typeAPIKey, typeServiceAccount, typeAnonymous, typeRenderService, typeAccessPolicy, typeProvisioning, typeEmpty:
		return nil
	default:
		return fmt.Errorf("invalid type %s: %w", n, ErrorInvalidSubjectType)
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
		return subject, fmt.Errorf("expected subject to have 2 parts: %w", ErrorInvalidSubject)
	}

	subject.ID = parts[1]
	subject.Type = subjectType(parts[0])

	err := subject.Type.isValid()
	if err != nil {
		return subject, err
	}

	return subject, nil
}
