package authn

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var (
	DefaultAccessTokenMetadataKey = "X-Access-Token"
	DefaultIdTokenMetadataKey     = "X-Id-Token"
)

// TODO (gamab): Make Access Token optional?
// TODO (gamab): Organization/Stack ID
// TODO (gamab): Readme

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
}

// GrpcClientInterceptor is a gRPC client interceptor that adds an access token to the outgoing context metadata.
type GrpcClientInterceptor struct {
	cfg         *GrpcClientConfig
	tokenClient TokenExchanger
	mdFns       []MetadataDecorator
}

type MetadataDecorator func(metadata.MD) (metadata.MD, error)

type GrpcClientInterceptorOption func(*GrpcClientInterceptor)

func WithTokenClientOption(tokenClient TokenExchanger) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		gci.tokenClient = tokenClient
	}
}

func WithIDTokenExtractorOption(extractor func(context.Context) (string, error)) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		WithMetadataDecoratorOption(func(md metadata.MD) (metadata.MD, error) {
			idToken, err := extractor(context.Background())
			if err != nil {
				return nil, err
			}
			md.Set(gci.cfg.IDTokenMetadataKey, idToken)
			return md, nil
		})(gci)
	}
}

func WithMetadataDecoratorOption(decorators ...MetadataDecorator) GrpcClientInterceptorOption {
	return func(gci *GrpcClientInterceptor) {
		gci.mdFns = append(gci.mdFns, decorators...)
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

	if gci.cfg.TokenRequest == nil {
		return nil, fmt.Errorf("missing required token request: %w", ErrMissingConfig)
	}

	for _, opt := range opts {
		opt(gci)
	}

	if gci.tokenClient == nil {
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

	token, err := gci.tokenClient.Exchange(ctx, *gci.cfg.TokenRequest)
	if err != nil {
		return ctx, err
	}

	md.Set(gci.cfg.AccessTokenMetadataKey, token.Token)

	if len(gci.mdFns) > 0 {
		for _, fn := range gci.mdFns {
			md, err = fn(md)
			if err != nil {
				return ctx, err
			}
		}
	}

	return metadata.NewOutgoingContext(ctx, md), nil
}