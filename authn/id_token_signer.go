package authn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/internal/httpclient"
	"github.com/grafana/dskit/backoff"
)

// IDTokenSigner signs ID tokens via the auth API.
type IDTokenSigner interface {
	SignIDToken(ctx context.Context, r SignIDTokenRequest, opts ...SignIDTokenOption) (*SignIDTokenResponse, error)
}

// SignIDTokenOption is a function that modifies the outgoing HTTP request for
// a single SignIDToken call. It is applied after default and client-level
// headers, so it can override anything. Use this for per-request concerns
// like setting tenant-scoped X-Org-ID / X-Realms headers.
type SignIDTokenOption func(*http.Request)

// WithSignerHeaders returns a SignIDTokenOption that sets the given HTTP
// headers on the request. This is a convenience helper for the common case
// of overriding headers per-request (e.g. X-Org-ID, X-Realms).
func WithSignerHeaders(headers map[string]string) SignIDTokenOption {
	return func(r *http.Request) {
		for k, v := range headers {
			r.Header.Set(k, v)
		}
	}
}

var _ IDTokenSigner = &IDTokenSignerClient{}

// IDTokenSignerClientOpts allows setting custom parameters during construction.
type IDTokenSignerClientOpts func(c *IDTokenSignerClient)

// WithIDTokenSignerHTTPClient allows setting the HTTP client to be used by the ID token signer client.
func WithIDTokenSignerHTTPClient(client *http.Client) IDTokenSignerClientOpts {
	return func(c *IDTokenSignerClient) {
		c.client = client
	}
}

// WithIDTokenSignerCache allows setting the cache to be used by the ID token signer client.
func WithIDTokenSignerCache(cache cache.Cache) IDTokenSignerClientOpts {
	return func(c *IDTokenSignerClient) {
		c.cache = cache
	}
}

// WithIDTokenSignerTracer allows setting the tracer to be used by the ID token signer client.
func WithIDTokenSignerTracer(tracer trace.Tracer) IDTokenSignerClientOpts {
	return func(c *IDTokenSignerClient) {
		c.tracer = tracer
	}
}


func NewIDTokenSignerClient(cfg IDTokenSignerConfig, opts ...IDTokenSignerClientOpts) (*IDTokenSignerClient, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: missing required token", ErrMissingConfig)
	}

	if cfg.SignIDTokenURL == "" {
		return nil, fmt.Errorf("%w: missing required sign ID token url", ErrMissingConfig)
	}

	c := &IDTokenSignerClient{
		cfg:     cfg,
		singlef: singleflight.Group{},
		tracer:  noop.NewTracerProvider().Tracer("authn.IDTokenSignerClient"),
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

	if c.cache == nil {
		c.cache = cache.NewLocalCache(cache.Config{
			CleanupInterval: 5 * time.Minute,
		})
	}

	return c, nil
}

type IDTokenSignerClient struct {
	cache        cache.Cache
	cfg          IDTokenSignerConfig
	client       *http.Client
	singlef      singleflight.Group
	tracer       trace.Tracer
	backoffCfg   backoff.Config
}

type SignIDTokenRequest struct {
	// Subject is the identity to sign the ID token for (e.g. "user:1").
	Subject string
	// Namespace is the namespace to scope the token to (e.g. "stacks-12345").
	Namespace string
	// Extra contains additional claims to include in the signed token
	// (e.g. email, username, type, role). Keys that conflict with
	// registered JWT claims are stripped server-side.
	Extra map[string]any
}

type SignIDTokenResponse struct {
	Token string
}

// signIDTokenRequestBody is the JSON body sent to the auth API.
type signIDTokenRequestBody struct {
	Claims    signIDTokenClaims `json:"claims"`
	Namespace string            `json:"namespace"`
	Extra     map[string]any    `json:"extra,omitempty"`
}

type signIDTokenClaims struct {
	Subject string `json:"sub"`
}

func (r SignIDTokenRequest) hash() string {
	if len(r.Extra) == 0 {
		return r.Subject + "-" + r.Namespace
	}
	h := sha256.New()
	h.Write([]byte(r.Subject))
	h.Write([]byte{0})
	h.Write([]byte(r.Namespace))
	h.Write([]byte{0})
	data, _ := json.Marshal(r.Extra)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

type signIDTokenResponseBody struct {
	Data   signIDTokenData `json:"data"`
	Status string          `json:"status"`
	Error  string          `json:"error"`
}

type signIDTokenData struct {
	Token string `json:"token"`
}

func (c *IDTokenSignerClient) SignIDToken(ctx context.Context, r SignIDTokenRequest, opts ...SignIDTokenOption) (*SignIDTokenResponse, error) {
	ctx, span := c.tracer.Start(ctx, "authn.IDTokenSignerClient.SignIDToken")
	defer span.End()
	span.SetAttributes(attribute.Bool("cache_hit", false))

	if r.Subject == "" {
		return nil, fmt.Errorf("%w: missing required subject", ErrMissingConfig)
	}

	if r.Namespace == "" {
		return nil, ErrMissingNamespace
	}

	key := r.hash()
	token, ok := c.getCache(ctx, key)
	if ok {
		span.SetAttributes(attribute.Bool("cache_hit", true))
		return &SignIDTokenResponse{Token: token}, nil
	}

	resp, err, _ := c.singlef.Do(key, func() (interface{}, error) {
		body := signIDTokenRequestBody{
			Claims:    signIDTokenClaims{Subject: r.Subject},
			Namespace: r.Namespace,
			Extra:     r.Extra,
		}

		data, err := json.Marshal(&body)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSignIDTokenResponse, err)
		}

		b := backoff.New(ctx, c.backoffCfg)

		var req *http.Request
		var res *http.Response
		for b.Ongoing() {
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.SignIDTokenURL, bytes.NewReader(data))
			if err != nil {
				return nil, fmt.Errorf("failed to build http request: %w", err)
			}

			req = c.withHeaders(req)
			for _, opt := range opts {
				opt(req)
			}

			res, err = c.client.Do(req)
			addResponseInformationToSpan(span, res, err)
			if shouldRetry(res, err) {
				if res != nil {
					_, _ = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()
				}

				b.Wait()
				continue
			}

			defer func() { _ = res.Body.Close() }()
			break
		}

		if err != nil || b.Err() != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSignIDTokenResponse, errors.Join(b.Err(), err))
		}

		if res.StatusCode >= http.StatusInternalServerError {
			return nil, fmt.Errorf("%w: %s", ErrInvalidSignIDTokenResponse, res.Status)
		}

		response := signIDTokenResponseBody{}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, err
		}

		if res.StatusCode != http.StatusOK {
			if response.Error != "" {
				return nil, fmt.Errorf("%w: %s", ErrInvalidSignIDTokenResponse, response.Error)
			}
			return nil, fmt.Errorf("%w: %s", ErrInvalidSignIDTokenResponse, res.Status)
		}

		_ = c.setCache(ctx, response.Data.Token, key)
		return &SignIDTokenResponse{Token: response.Data.Token}, nil
	})

	if err != nil {
		return nil, err
	}

	return resp.(*SignIDTokenResponse), nil
}

func (c *IDTokenSignerClient) withHeaders(r *http.Request) *http.Request {
	r.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "authlib-client")

	// Default system-scoped headers.
	r.Header.Set("X-Org-ID", "0")
	r.Header.Set("X-Realms", `[{"type": "system", "identifier": "system"}]`)

	// Propagate OpenTelemetry context headers.
	otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))

	return r
}

func (c *IDTokenSignerClient) getCache(ctx context.Context, key string) (string, bool) {
	if token, err := c.cache.Get(ctx, key); err == nil {
		return string(token), true
	}
	return "", false
}

func (c *IDTokenSignerClient) setCache(ctx context.Context, token string, key string) error {
	const cacheLeeway = 15 * time.Second

	parsed, err := jwt.ParseSigned(token, tokenSignAlgs)
	if err != nil {
		return fmt.Errorf("failed to parse token: %v", err)
	}

	var claims jwt.Claims
	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return fmt.Errorf("failed to extract claims from the token: %v", err)
	}

	return c.cache.Set(ctx, key, []byte(token), time.Until(claims.Expiry.Time())-cacheLeeway)
}
