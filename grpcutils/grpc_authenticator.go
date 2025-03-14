package grpcutils

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Authenticator interface {
	Authenticate(ctx context.Context) (context.Context, error)
}

type GAuthenticatorFunc func(context.Context) (context.Context, error)

func (fn GAuthenticatorFunc) Authenticate(ctx context.Context) (context.Context, error) {
	return fn(ctx)
}

func NewUnsafeAuthenticator(tracer trace.Tracer) Authenticator {
	return NewAuthenticatorInterceptor(
		authn.NewDefaultAuthenticator(
			authn.NewUnsafeAccessTokenVerifier(authn.VerifierConfig{}),
			authn.NewUnsafeIDTokenVerifier(authn.VerifierConfig{}),
		),
		noop.NewTracerProvider().Tracer(""),
	)
}

func NewAuthenticator(cfg *GrpcAuthenticatorConfig, tracer trace.Tracer) Authenticator {
	client := http.DefaultClient
	if cfg.AllowInsecure {
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}

	kr := authn.NewKeyRetriever(authn.KeyRetrieverConfig{
		SigningKeysURL: cfg.SigningKeysURL,
	}, authn.WithHTTPClientKeyRetrieverOpt(client))

	auth := authn.NewDefaultAuthenticator(
		authn.NewAccessTokenVerifier(authn.VerifierConfig{AllowedAudiences: cfg.AllowedAudiences}, kr),
		authn.NewIDTokenVerifier(authn.VerifierConfig{}, kr),
	)

	return NewAuthenticatorInterceptor(auth, tracer)
}

func NewAuthenticatorInterceptor(auth authn.Authenticator, tracer trace.Tracer) Authenticator {
	return GAuthenticatorFunc(func(ctx context.Context) (context.Context, error) {
		ctx, span := tracer.Start(ctx, "grpcutils.Authenticate")
		defer span.End()

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, errors.New("missing metedata in context")
		}

		info, err := auth.Authenticate(ctx, authn.NewGRPCTokenProvider(md))
		if err != nil {
			span.RecordError(err)
			if authn.IsUnauthenticatedErr(err) {
				return nil, status.Error(codes.Unauthenticated, err.Error())
			}

			return ctx, status.Error(codes.Internal, err.Error())
		}

		// FIXME: Add attribute with service subject once https://github.com/grafana/authlib/issues/139 is closed.
		span.SetAttributes(attribute.String("subject", info.GetUID()))
		span.SetAttributes(attribute.Bool("service", types.IsIdentityType(info.GetIdentityType(), types.TypeAccessPolicy)))
		return types.WithAuthInfo(ctx, info), nil
	})
}
