package authn

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc"
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

type AuthenticatePayload struct {
	Metadata          metadata.MD
	AccessTokenClaims *Claims[AccessTokenClaims]
	IDTokenClaims     *Claims[IDTokenClaims]
	Request           any
}

type RequestWithStack interface {
	GetStackID() int64
}

type ServiceAuthFuncOverride interface {
	AuthFuncOverride(ctx context.Context, payload AuthenticatePayload) (context.Context, error)
}

// GrpcAuthenticatorOptions
type GrpcAuthenticatorOption func(*GrpcAuthenticatorImpl)

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

	// stackIDExtractor is a function that extracts the stack ID from the incoming metadata, tokens or request.
	stackIDExtractor func(AuthenticatePayload) (int64, error)

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

// GrpcAuthenticatorImpl is a gRPC authenticator that authenticates incoming requests based on the access token and ID token.
type GrpcAuthenticatorImpl struct {
	cfg          *GrpcAuthenticatorConfig
	keyRetriever KeyRetriever
	atVerifier   Verifier[AccessTokenClaims]
	idVerifier   Verifier[IDTokenClaims]
	namespaceFmt NamespaceFormatter
}

func WithKeyRetrieverOption(kr KeyRetriever) GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticatorImpl) {
		ga.keyRetriever = kr
	}
}

// WithIDTokenAuthOption is a flag to enable ID token authentication.
// If required is true, the ID token is required for authentication.
func WithIDTokenAuthOption(required bool) GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticatorImpl) {
		ga.cfg.idTokenAuthEnabled = true
		ga.cfg.idTokenAuthRequired = required
	}
}

// WithDisableAccessTokenAuthOption is an option to disable access token authentication.
// Warning: Using this option means there won't be any service authentication.
func WithDisableAccessTokenAuthOption() GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticatorImpl) {
		ga.cfg.accessTokenAuthEnabled = false
	}
}

func WithMetadataStackIDExtractorAuthOption() GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticatorImpl) {
		ga.cfg.stackIDExtractor = func(ap AuthenticatePayload) (int64, error) {
			stackID, ok := getFirstMetadataValue(ap.Metadata, ga.cfg.StackIDMetadataKey)
			if !ok {
				return -1, fmt.Errorf("missing stack ID: %w", ErrorMissingMetadata)
			}
			stackIDInt, err := strconv.ParseInt(stackID, 10, 64)
			if err != nil {
				return -1, fmt.Errorf("failed to parse stack ID: %w", ErrorInvalidStackID)
			}
			return stackIDInt, nil
		}
	}
}

func WithRequestStackIDExtractorAuthOption() GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticatorImpl) {
		ga.cfg.stackIDExtractor = func(ap AuthenticatePayload) (int64, error) {
			if req, ok := ap.Request.(RequestWithStack); ok {
				return req.GetStackID(), nil
			}
			return -1, fmt.Errorf("missing stack ID: %w", ErrorMissingMetadata)
		}
	}
}

// TODO (gamab): WithIDTokenStackIDExtractorAuthOption - this will require the opposite of NamespaceFormatter
// func WithIDTokenStackIDExtractorAuthOption() GrpcAuthenticatorOption {
// }

func WithStackIDExtractorAuthOption(extractor func(AuthenticatePayload) (int64, error)) GrpcAuthenticatorOption {
	return func(ga *GrpcAuthenticatorImpl) {
		ga.cfg.stackIDExtractor = extractor
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

func NewGrpcAuthenticator(cfg *GrpcAuthenticatorConfig, opts ...GrpcAuthenticatorOption) (*GrpcAuthenticatorImpl, error) {
	setGrpcAuthenticatorCfgDefaults(cfg)

	ga := &GrpcAuthenticatorImpl{cfg: cfg}
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

func (ga *GrpcAuthenticatorImpl) extractPayload(ctx context.Context, req any) (AuthenticatePayload, error) {
	res := AuthenticatePayload{Request: req}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return res, ErrorMissingMetadata
	}
	res.Metadata = md

	if ga.cfg.accessTokenAuthEnabled {
		at, ok := getFirstMetadataValue(md, ga.cfg.AccessTokenMetadataKey)
		if !ok {
			return res, ErrorMissingAccessToken
		}

		claims, err := ga.atVerifier.Verify(ctx, at)
		if err != nil {
			return res, fmt.Errorf("%v: %w", err, ErrorInvalidAccessToken)
		}
		res.AccessTokenClaims = claims
	}

	if ga.cfg.idTokenAuthEnabled {
		id, ok := getFirstMetadataValue(md, ga.cfg.IDTokenMetadataKey)
		if !ok {
			if ga.cfg.idTokenAuthRequired {
				return res, ErrorMissingIDToken
			}
		} else {
			claims, err := ga.idVerifier.Verify(ctx, id)
			if err != nil {
				return res, fmt.Errorf("%v: %w", err, ErrorInvalidIDToken)
			}
			res.IDTokenClaims = claims
		}
	}

	return res, nil
}

func (ga *GrpcAuthenticatorImpl) Authenticate(ctx context.Context, payload AuthenticatePayload) (context.Context, error) {
	callerInfo := CallerAuthInfo{}

	stackID, err := ga.cfg.stackIDExtractor(payload)
	if err != nil {
		return nil, err
	}
	expectedNamespace := ga.namespaceFmt(stackID)

	if ga.cfg.accessTokenAuthEnabled {
		if payload.AccessTokenClaims == nil {
			return nil, ErrorMissingAccessToken
		}
		if err := ga.authenticateService(ctx, expectedNamespace, payload.AccessTokenClaims); err != nil {
			return nil, err
		}
		callerInfo.AccessTokenClaims = *payload.AccessTokenClaims
	}

	if ga.cfg.idTokenAuthEnabled {
		if payload.IDTokenClaims == nil {
			if ga.cfg.idTokenAuthRequired {
				return nil, ErrorMissingIDToken
			}
		}
		if err := ga.authenticateUser(ctx, expectedNamespace, payload.IDTokenClaims); err != nil {
			return nil, err
		}
		callerInfo.IDTokenClaims = payload.IDTokenClaims
	}

	return AddCallerAuthInfoToContext(ctx, callerInfo), nil
}

func (ga *GrpcAuthenticatorImpl) authenticateService(ctx context.Context, expectedNamespace string, claims *Claims[AccessTokenClaims]) error {
	// Allow access tokens with that has a wildcard namespace or a namespace matching this instance.
	if !claims.Rest.NamespaceMatches(expectedNamespace) {
		return fmt.Errorf("unexpected access token namespace '%s': %w", claims.Rest.Namespace, ErrorInvalidAccessToken)
	}

	subject, err := parseSubject(claims.Subject)
	if err != nil {
		return fmt.Errorf("access token subject '%s' is not valid: %w", claims.Subject, err)
	}

	if subject.Type != typeAccessPolicy {
		return fmt.Errorf("access token subject '%s' type is not allowed: %w", subject.Type, ErrorInvalidSubjectType)
	}

	return nil
}

func (ga *GrpcAuthenticatorImpl) authenticateUser(ctx context.Context, expectedNamespace string, claims *Claims[IDTokenClaims]) error {
	if claims.Rest.Namespace != expectedNamespace {
		return fmt.Errorf("unexpected id token namespace '%s': %w", claims.Rest.Namespace, ErrorInvalidIDToken)
	}

	subject, err := parseSubject(claims.Subject)
	if err != nil {
		return fmt.Errorf("id token subject '%s' is not valid: %w", claims.Subject, err)
	}

	if subject.Type != typeUser && subject.Type != typeServiceAccount {
		return fmt.Errorf("id token subject '%s' type is not allowed: %w", subject.Type, ErrorInvalidSubjectType)
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

func (ga *GrpcAuthenticatorImpl) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		payload, err := ga.extractPayload(ctx, req)
		if err != nil {
			return nil, err
		}

		var newCtx context.Context
		if overrideSrv, ok := info.Server.(ServiceAuthFuncOverride); ok {
			newCtx, err = overrideSrv.AuthFuncOverride(ctx, payload)
		} else {
			newCtx, err = ga.Authenticate(ctx, payload)
		}
		if err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}

type grpcAuthenticatorStreamWrapper struct {
	grpc.ServerStream
	srv any
	ga  *GrpcAuthenticatorImpl
	ctx context.Context
}

func (w *grpcAuthenticatorStreamWrapper) RecvMsg(m any) error {
	payload, err := w.ga.extractPayload(w.Context(), m)
	if err != nil {
		return err
	}

	var newCtx context.Context
	if overrideSrv, ok := w.srv.(ServiceAuthFuncOverride); ok {
		newCtx, err = overrideSrv.AuthFuncOverride(w.Context(), payload)
	} else {
		newCtx, err = w.ga.Authenticate(w.Context(), payload)
	}
	if err != nil {
		return err
	}

	w.ctx = newCtx

	return w.ServerStream.RecvMsg(m)
}

func (w *grpcAuthenticatorStreamWrapper) Context() context.Context {
	return w.ctx
}

// TODO (gamab): Can we implement this?
func (ga *GrpcAuthenticatorImpl) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &grpcAuthenticatorStreamWrapper{ServerStream: stream, ga: ga, srv: srv, ctx: stream.Context()})
	}
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
