package authn

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	DefaultAccessTokenMetadataKey = "X-Access-Token"
	DefaultIdTokenMetadataKey     = "X-Id-Token"
)

// GrpcClientConfig holds the configuration for the gRPC client interceptor.
type GrpcClientConfig struct {
	// DisableAccessToken is a flag to disable the access token.
	// Warning: Using this options means there won't be any servie authentication.
	DisableAccessToken bool
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
}

// GrpcClientInterceptor is a gRPC client interceptor that adds an access token to the outgoing context metadata.
type GrpcClientInterceptor struct {
	cfg                *GrpcClientConfig
	tokenClient        TokenExchanger
	metadataExtractors []ContextMetadataExtractor
}

type ContextMetadataExtractor func(context.Context) (key string, values []string, err error)

type GrpcClientInterceptorOption func(*GrpcClientInterceptor)

func WithTokenClientOption(tokenClient TokenExchanger) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		gci.tokenClient = tokenClient
	}
}

func WithIDTokenExtractorOption(extractor func(context.Context) (string, error)) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		WithMetadataExtractorOption(func(ctx context.Context) (key string, values []string, err error) {
			idToken, err := extractor(ctx)
			if err != nil {
				return "", nil, err
			}
			return gci.cfg.IDTokenMetadataKey, []string{idToken}, nil
		})(gci)
	}
}

func WithMetadataExtractorOption(extractors ...ContextMetadataExtractor) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		gci.metadataExtractors = append(gci.metadataExtractors, extractors...)
	}
}

func NewGrpcClientInterceptor(cfg *GrpcClientConfig, opts ...GrpcClientInterceptorOption) (*GrpcClientInterceptor, error) {
	gci := &GrpcClientInterceptor{cfg: cfg}

	if gci.cfg.AccessTokenMetadataKey == "" {
		gci.cfg.AccessTokenMetadataKey = DefaultAccessTokenMetadataKey
	}
	if gci.cfg.IDTokenMetadataKey == "" {
		gci.cfg.IDTokenMetadataKey = DefaultIdTokenMetadataKey
	}

	if gci.cfg.TokenRequest == nil && !gci.cfg.DisableAccessToken {
		return nil, fmt.Errorf("missing required token request: %w", ErrMissingConfig)
	}

	for _, opt := range opts {
		opt(gci)
	}

	if gci.tokenClient == nil && !gci.cfg.DisableAccessToken {
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
	md := metadata.Pairs()

	if !gci.cfg.DisableAccessToken {
		token, err := gci.tokenClient.Exchange(ctx, *gci.cfg.TokenRequest)
		if err != nil {
			return ctx, err
		}

		md.Set(gci.cfg.AccessTokenMetadataKey, token.Token)
	}

	for _, extract := range gci.metadataExtractors {
		k, v, err := extract(ctx)
		if err != nil {
			return ctx, err
		}
		md.Set(k, v...)
	}

	return metadata.NewOutgoingContext(ctx, md), nil
}
