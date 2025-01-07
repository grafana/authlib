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
	// TokenRequest is the token request to be used for token exchange.
	// This assumes the token request is static and does not change.
	TokenRequest *TokenExchangeRequest
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

// WithTracerOption sets the tracer for the gRPC authenticator.
func WithTracerOption(tracer trace.Tracer) GrpcClientInterceptorOption {
	return func(c *GrpcClientInterceptor) {
		c.tracer = tracer
	}
}

func NewGrpcClientInterceptor(tokenClient TokenExchanger, cfg *GrpcClientConfig, opts ...GrpcClientInterceptorOption) (*GrpcClientInterceptor, error) {
	gci := &GrpcClientInterceptor{
		cfg:         cfg,
		tokenClient: tokenClient,
	}

	for _, opt := range opts {
		opt(gci)
	}

	if gci.tracer == nil {
		gci.tracer = noop.Tracer{}
	}

	if gci.cfg.TokenRequest == nil {
		return nil, fmt.Errorf("missing required token request: %w", ErrMissingConfig)
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

	token, err := gci.tokenClient.Exchange(spanCtx, *gci.cfg.TokenRequest)
	if err != nil {
		span.RecordError(err)
		return ctx, err
	}

	span.SetAttributes(attribute.Bool("with_accesstoken", true))
	md.Set(DefaultAccessTokenMetadataKey, token.Token)

	if gci.idTokenExtractor != nil {
		idToken, err := gci.idTokenExtractor(spanCtx)
		if err != nil {
			span.RecordError(err)
			return ctx, err
		}
		if idToken != "" {
			span.SetAttributes(attribute.Bool("with_idtoken", true))
			md.Set(DefaultIdTokenMetadataKey, idToken)
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
