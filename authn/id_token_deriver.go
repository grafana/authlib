package authn

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/internal/httpclient"
	"github.com/grafana/dskit/backoff"
)

// IDTokenDeriver mints an id token identifying the user or service account embedded in an
// on-behalf-of access token's actor chain. It is for callers that hold an access token instead of
// a directly-asserted subject; compare IDTokenSigner, which signs a directly-asserted subject.
type IDTokenDeriver interface {
	DeriveIDToken(ctx context.Context, subjectToken, namespace string) (*DeriveIDTokenResponse, error)
}

type DeriveIDTokenResponse struct {
	Token string
}

// IDTokenDeriveConfig configures IDTokenDeriveClient. Both fields are required to construct a
// client: DeriveIDTokenURL has no safe default, and Token is the same system-realm CAP token used
// for TokenExchangeConfig.
type IDTokenDeriveConfig struct {
	// Token used to authenticate to the derive-id-token endpoint.
	Token string `yaml:"token"`
	// Url called to derive an id token from a subject access token.
	DeriveIDTokenURL string `yaml:"deriveIdTokenUrl"`
}

func (c *IDTokenDeriveConfig) RegisterFlags(prefix string, fs *flag.FlagSet) {
	fs.StringVar(&c.Token, prefix+".token", "", "Token used to authenticate to the derive-id-token endpoint.")
	fs.StringVar(&c.DeriveIDTokenURL, prefix+".derive-id-token-url", "", "Url called to derive an id token from a subject access token.")
}

var _ IDTokenDeriver = &IDTokenDeriveClient{}

// IDTokenDeriveClientOpts allows setting custom parameters during construction.
type IDTokenDeriveClientOpts func(c *IDTokenDeriveClient)

// WithIDTokenDeriveHTTPClient allows setting the HTTP client to be used by the derive client.
func WithIDTokenDeriveHTTPClient(client *http.Client) IDTokenDeriveClientOpts {
	return func(c *IDTokenDeriveClient) {
		c.client = client
	}
}

// WithIDTokenDeriveCache allows setting the cache to be used by the derive client.
func WithIDTokenDeriveCache(cache cache.Cache) IDTokenDeriveClientOpts {
	return func(c *IDTokenDeriveClient) {
		c.tc.cache = cache
	}
}

// WithIDTokenDeriveTracer allows setting the tracer to be used by the derive client.
func WithIDTokenDeriveTracer(tracer trace.Tracer) IDTokenDeriveClientOpts {
	return func(c *IDTokenDeriveClient) {
		c.tracer = tracer
	}
}

// NewIDTokenDeriveClient constructs an IDTokenDeriveClient. Unlike TokenExchangeConfig,
// DeriveIDTokenURL has no fallback: a service that never derives id tokens simply doesn't
// construct one, but a service that does must configure both fields or fail fast at startup
// rather than fail on the first call.
func NewIDTokenDeriveClient(cfg IDTokenDeriveConfig, opts ...IDTokenDeriveClientOpts) (*IDTokenDeriveClient, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: missing required token", ErrMissingConfig)
	}

	if cfg.DeriveIDTokenURL == "" {
		return nil, fmt.Errorf("%w: missing required derive id token url", ErrMissingConfig)
	}

	c := &IDTokenDeriveClient{
		tc:     &tokenCache{}, // cache set below.
		cfg:    cfg,
		tracer: noop.NewTracerProvider().Tracer("authn.IDTokenDeriveClient"),
		backoffCfg: backoff.Config{
			MaxBackoff: time.Second,
			MinBackoff: 250 * time.Millisecond,
			MaxRetries: 3,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.client == nil {
		c.client = httpclient.New()
	}

	// See NewTokenExchangeClient for why this can't be a default struct field value.
	if c.tc.cache == nil {
		c.tc.cache = cache.NewLocalCache(cache.Config{
			CleanupInterval: 5 * time.Minute,
		})
	}

	return c, nil
}

type IDTokenDeriveClient struct {
	tc         *tokenCache
	cfg        IDTokenDeriveConfig
	client     *http.Client
	tracer     trace.Tracer
	backoffCfg backoff.Config
}

type deriveIDTokenRequestBody struct {
	SubjectToken string `json:"subjectToken"`
	Namespace    string `json:"namespace"`
}

func (c *IDTokenDeriveClient) DeriveIDToken(ctx context.Context, subjectToken, namespace string) (*DeriveIDTokenResponse, error) {
	ctx, span := c.tracer.Start(ctx, "authn.IDTokenDeriveClient.DeriveIDToken")
	defer span.End()

	if subjectToken == "" {
		return nil, ErrMissingSubjectToken
	}

	if namespace == "" {
		return nil, ErrMissingNamespace
	}

	// Prefixed so this never collides with a TokenExchangeClient cache entry, in case both
	// clients ever shared a cache instance.
	key := "derive-" + namespace + "-" + subjectTokenCacheKey(subjectToken)

	token, hit, err := c.tc.getOrFetch(ctx, key, func() (string, error) {
		data, err := json.Marshal(&deriveIDTokenRequestBody{SubjectToken: subjectToken, Namespace: namespace})
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidDeriveIDTokenResponse, err)
		}

		return postForToken(ctx, c.client, c.backoffCfg, span, c.cfg.DeriveIDTokenURL, c.cfg.Token, data, ErrInvalidDeriveIDTokenResponse)
	})
	span.SetAttributes(attribute.Bool("cache_hit", hit))
	if err != nil {
		return nil, err
	}

	return &DeriveIDTokenResponse{Token: token}, nil
}
