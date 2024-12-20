package authn

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	DefaultAccessTokenMetadataKey = "X-Access-Token"
	DefaultIdTokenMetadataKey     = "X-Id-Token"
)

// GrpcClientConfig holds the configuration for the gRPC client interceptor.
type GrpcClientConfig struct {
	// AccessTokenMetadataKey is the key used to store the access token in the outgoing context metadata.
	// Defaults to "X-Access-Token".
	AccessTokenMetadataKey string
	// IDTokenMetadataKey is the key used to store the ID token in the outgoing context metadata.
	// Not required if IDTokenExtractor is provided. Defaults to "X-Id-Token".
	IDTokenMetadataKey string
	// TokenClientConfig holds the configuration for the token exchange client.
	// Not required if TokenClient is provided.
	TokenClientConfig *TokenExchangeConfig
	// TokenRequest is the token request to be used for token exchange.
	// This assumes the token request is static and does not change.
	TokenRequest *TokenExchangeRequest

	// accessTokenAuthEnabled is a flag to enable access token authentication.
	// If disabled, no service authentication will be performed. Defaults to true.
	accessTokenAuthEnabled bool
}

// GrpcClientInterceptor is a gRPC client interceptor that adds an access token to the outgoing context metadata.
type GrpcClientInterceptor struct {
	cfg                *GrpcClientConfig
	tokenClient        TokenExchanger
	idTokenExtractor   func(context.Context) (string, error)
	metadataExtractors []ContextMetadataExtractor
	tracer             trace.Tracer
}

type ContextMetadataExtractor func(context.Context) (key string, values []string, err error)

type GrpcClientInterceptorOption func(*GrpcClientInterceptor)

func WithTokenClientOption(tokenClient TokenExchanger) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		gci.tokenClient = tokenClient
	}
}

// WithIDTokenExtractorOption is an option to set the ID token extractor for the gRPC client interceptor.
// Warning: The id_token will be considered optional if the extractor returns an empty string.
// Returning an error will stop the interceptor.
func WithIDTokenExtractorOption(extractor func(context.Context) (string, error)) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		gci.idTokenExtractor = extractor
	}
}

func WithMetadataExtractorOption(extractors ...ContextMetadataExtractor) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		gci.metadataExtractors = append(gci.metadataExtractors, extractors...)
	}
}

// WithDisableAccessTokenOption is an option to disable access token authentication.
// Warning: Using this option means there won't be any service authentication.
func WithDisableAccessTokenOption() GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		gci.cfg.accessTokenAuthEnabled = false
	}
}

// WithTracerOption sets the tracer for the gRPC authenticator.
func WithTracerOption(tracer trace.Tracer) GrpcClientInterceptorOption {
	return func(c *GrpcClientInterceptor) {
		c.tracer = tracer
	}
}

func setGrpcClientCfgDefaults(cfg *GrpcClientConfig) {
	if cfg.AccessTokenMetadataKey == "" {
		cfg.AccessTokenMetadataKey = DefaultAccessTokenMetadataKey
	}
	if cfg.IDTokenMetadataKey == "" {
		cfg.IDTokenMetadataKey = DefaultIdTokenMetadataKey
	}
	cfg.accessTokenAuthEnabled = true
}

func NewGrpcClientInterceptor(cfg *GrpcClientConfig, opts ...GrpcClientInterceptorOption) (*GrpcClientInterceptor, error) {
	setGrpcClientCfgDefaults(cfg)
	gci := &GrpcClientInterceptor{cfg: cfg}

	for _, opt := range opts {
		opt(gci)
	}

	if gci.tracer == nil {
		gci.tracer = noop.Tracer{}
	}

	if gci.cfg.TokenRequest == nil && gci.cfg.accessTokenAuthEnabled {
		return nil, fmt.Errorf("missing required token request: %w", ErrMissingConfig)
	}

	if gci.tokenClient == nil && gci.cfg.accessTokenAuthEnabled {
		if gci.cfg.TokenClientConfig == nil {
			return nil, fmt.Errorf("missing required token client config: %w", ErrMissingConfig)
		}

		tokenClient, err := NewTokenExchangeClient(*gci.cfg.TokenClientConfig)
		if err != nil {
			return nil, err
		}
		gci.tokenClient = tokenClient
	}

	return gci, nil
}

func (gci *GrpcClientInterceptor) UnaryClientInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	ctx, err := gci.wrapContext(ctx)
	if err != nil {
		return err
	}

	return invoker(ctx, method, req, reply, cc, opts...)
}

func (gci *GrpcClientInterceptor) StreamClientInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	ctx, err := gci.wrapContext(ctx)
	if err != nil {
		return nil, err
	}

	return streamer(ctx, desc, cc, method, opts...)
}

func (gci *GrpcClientInterceptor) wrapContext(ctx context.Context) (context.Context, error) {
	spanCtx, span := gci.tracer.Start(ctx, "GrpcClientInterceptor.wrapContext")
	defer span.End()

	md := metadata.Pairs()

	if gci.cfg.accessTokenAuthEnabled {
		token, err := gci.tokenClient.Exchange(spanCtx, *gci.cfg.TokenRequest)
		if err != nil {
			span.RecordError(err)
			return ctx, err
		}

		span.SetAttributes(attribute.Bool("with_accesstoken", true))
		md.Set(gci.cfg.AccessTokenMetadataKey, token.Token)
	}

	if gci.idTokenExtractor != nil {
		idToken, err := gci.idTokenExtractor(spanCtx)
		if err != nil {
			span.RecordError(err)
			return ctx, err
		}
		if idToken != "" {
			span.SetAttributes(attribute.Bool("with_idtoken", true))
			md.Set(gci.cfg.IDTokenMetadataKey, idToken)
		}
	}

	keys := make([]string, 0, len(gci.metadataExtractors))
	for _, extract := range gci.metadataExtractors {
		k, v, err := extract(spanCtx)
		if err != nil {
			span.RecordError(err)
			return ctx, err
		}
		keys = append(keys, k)
		md.Set(k, v...)
		span.SetAttributes(attribute.String("keys", strings.Join(keys, ",")))
	}

	return metadata.NewOutgoingContext(ctx, md), nil
}
