package authn

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grafana/authlib/types"
)

var (
	ErrorMissingMetadata    = status.Error(codes.Unauthenticated, "unauthenticated: no metadata found")
	ErrorMissingIDToken     = status.Error(codes.Unauthenticated, "unauthenticated: missing id token")
	ErrorMissingAccessToken = status.Error(codes.Unauthenticated, "unauthenticated: missing access token")
	ErrorInvalidIDToken     = status.Error(codes.PermissionDenied, "unauthorized: invalid id token")
	ErrorInvalidAccessToken = status.Error(codes.PermissionDenied, "unauthorized: invalid access token")
	ErrorNamespacesMismatch = status.Error(codes.PermissionDenied, "unauthorized: access and id token namespaces mismatch")
	ErrorInvalidSubject     = status.Error(codes.PermissionDenied, "unauthorized: invalid subject")
	ErrorInvalidSubjectType = status.Error(codes.PermissionDenied, "unauthorized: invalid subject type")
)

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

	// KeyRetrieverConfig holds the configuration for the key retriever.
	// Ignored if KeyRetrieverOption is provided or when unsafe verifiers are used via NewUnsafeGrpcAuthenticator.
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
	tracer       trace.Tracer
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

// WithTracerAuthOption sets the tracer for the gRPC authenticator.
func WithTracerAuthOption(tracer trace.Tracer) GrpcAuthenticatorOption {
	return func(c *GrpcAuthenticator) {
		c.tracer = tracer
	}
}

func setGrpcAuthenticatorCfgDefaults(cfg *GrpcAuthenticatorConfig) {
	if cfg.AccessTokenMetadataKey == "" {
		cfg.AccessTokenMetadataKey = DefaultAccessTokenMetadataKey
	}
	if cfg.IDTokenMetadataKey == "" {
		cfg.IDTokenMetadataKey = DefaultIdTokenMetadataKey
	}
	cfg.accessTokenAuthEnabled = true
}

// NewGrpcAuthenticator creates a new gRPC authenticator that uses safe verifiers (i.e. JWT signature is checked).
// If a KeyRetriever is not provided via WithKeyRetrieverOption, a default one is created using the configuration
// provided via GrpcAuthenticatorConfig.KeyRetrieverConfig.
func NewGrpcAuthenticator(cfg *GrpcAuthenticatorConfig, opts ...GrpcAuthenticatorOption) (*GrpcAuthenticator, error) {
	ga := newGrpcAuthenticatorCommon(cfg, opts...)

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
		// Skip audience checks for ID tokens (reset AllowedAudiences)
		verifierConfig := cfg.VerifierConfig
		verifierConfig.AllowedAudiences = []string{}
		ga.idVerifier = NewIDTokenVerifier(verifierConfig, ga.keyRetriever)
	}

	return ga, nil
}

// NewUnsafeGrpcAuthenticator creates a new gRPC authenticator that uses unsafe verifiers (i.e. JWT signature is not checked).
// Unsafe verifiers do not perform key retrieval and JWT signtature validation. **Use with caution**.
func NewUnsafeGrpcAuthenticator(cfg *GrpcAuthenticatorConfig, opts ...GrpcAuthenticatorOption) *GrpcAuthenticator {
	ga := newGrpcAuthenticatorCommon(cfg, opts...)

	if ga.cfg.accessTokenAuthEnabled {
		ga.atVerifier = NewUnsafeAccessTokenVerifier(cfg.VerifierConfig)
	}

	if ga.cfg.idTokenAuthEnabled {
		// Skip audience checks for ID tokens (reset AllowedAudiences)
		verifierConfig := cfg.VerifierConfig
		verifierConfig.AllowedAudiences = []string{}
		ga.idVerifier = NewUnsafeIDTokenVerifier(verifierConfig)
	}

	return ga
}

// Authenticate authenticates the incoming request based on the access token and ID token, and returns the context with the caller information.
func (ga *GrpcAuthenticator) Authenticate(ctx context.Context) (context.Context, error) {
	spanCtx, span := ga.tracer.Start(ctx, "GrpcAuthenticator.Authenticate")
	defer span.End()

	authInfo := AuthInfo{}

	md, ok := metadata.FromIncomingContext(spanCtx)
	if !ok {
		span.RecordError(ErrorMissingMetadata)
		return nil, ErrorMissingMetadata
	}

	var at *Claims[AccessTokenClaims]
	if ga.cfg.accessTokenAuthEnabled {
		var err error
		at, err = ga.authenticateService(spanCtx, md)
		if err != nil {
			span.RecordError(err)
			return nil, err
		}
		span.SetAttributes(attribute.Bool("with_accesstoken", true))
		span.SetAttributes(attribute.String("service", at.Subject))
		authInfo.at = *at
	}

	var id *Claims[IDTokenClaims]
	if ga.cfg.idTokenAuthEnabled {
		var err error
		id, err = ga.authenticateUser(spanCtx, md)
		if err != nil {
			span.RecordError(err)
			return nil, err
		}
		if id != nil {
			span.SetAttributes(attribute.Bool("with_idtoken", true))
			span.SetAttributes(attribute.String("user", id.Subject))
			authInfo.id = id
		}
	}

	// Validate accessToken namespace matches IDToken namespace
	if ga.cfg.accessTokenAuthEnabled && ga.cfg.idTokenAuthEnabled && id != nil {
		if !types.NamespaceMatches(at.Rest.Namespace, id.Rest.Namespace) {
			span.RecordError(ErrorNamespacesMismatch)
			return nil, ErrorNamespacesMismatch
		}
	}

	return types.WithClaims(ctx, &authInfo), nil
}

func (ga *GrpcAuthenticator) authenticateService(ctx context.Context, md metadata.MD) (*Claims[AccessTokenClaims], error) {
	at, ok := getFirstMetadataValue(md, ga.cfg.AccessTokenMetadataKey)
	if !ok {
		return nil, ErrorMissingAccessToken
	}

	atClaims, err := ga.atVerifier.Verify(ctx, at)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, ErrorInvalidAccessToken)
	}

	typ, _, err := types.ParseTypeID(atClaims.Subject)
	if err != nil {
		return nil, fmt.Errorf("access token subject '%s' is not valid: %w", atClaims.Subject, ErrorInvalidSubject)
	}

	if typ != types.TypeAccessPolicy {
		return nil, fmt.Errorf("access token subject '%s' type is not allowed: %w", typ, ErrorInvalidSubjectType)
	}

	return atClaims, nil
}

func (ga *GrpcAuthenticator) authenticateUser(ctx context.Context, md metadata.MD) (*Claims[IDTokenClaims], error) {
	id, ok := getFirstMetadataValue(md, ga.cfg.IDTokenMetadataKey)
	if !ok {
		if ga.cfg.idTokenAuthRequired {
			return nil, ErrorMissingIDToken
		}
		return nil, nil
	}

	idClaims, err := ga.idVerifier.Verify(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, ErrorInvalidIDToken)
	}

	_, _, err = types.ParseTypeID(idClaims.Subject)
	if err != nil {
		return nil, fmt.Errorf("id token subject '%s' is not valid: %w", idClaims.Subject, ErrorInvalidSubject)
	}

	return idClaims, nil
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

func newGrpcAuthenticatorCommon(cfg *GrpcAuthenticatorConfig, opts ...GrpcAuthenticatorOption) *GrpcAuthenticator {
	setGrpcAuthenticatorCfgDefaults(cfg)

	ga := &GrpcAuthenticator{cfg: cfg}
	for _, opt := range opts {
		opt(ga)
	}

	if ga.tracer == nil {
		ga.tracer = noop.Tracer{}
	}

	return ga
}
