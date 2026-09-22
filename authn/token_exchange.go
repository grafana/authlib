package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/internal/httpclient"
	"github.com/grafana/dskit/backoff"
)

// Provided for mockability of client
type TokenExchanger interface {
	Exchange(ctx context.Context, r TokenExchangeRequest) (*TokenExchangeResponse, error)
}

var _ TokenExchanger = &TokenExchangeClient{}

// ExchangeClientOpts allows setting custom parameters during construction.
type ExchangeClientOpts func(c *TokenExchangeClient)

// WithHTTPClient allows setting the HTTP client to be used by the token exchange client.
func WithHTTPClient(client *http.Client) ExchangeClientOpts {
	return func(c *TokenExchangeClient) {
		c.client = client
	}
}

func WithTokenExchangeClientCache(cache cache.Cache) ExchangeClientOpts {
	return func(c *TokenExchangeClient) {
		c.tc.cache = cache
	}
}

func WithTracer(tracer trace.Tracer) ExchangeClientOpts {
	return func(c *TokenExchangeClient) {
		c.tracer = tracer
	}
}

func NewTokenExchangeClient(cfg TokenExchangeConfig, opts ...ExchangeClientOpts) (*TokenExchangeClient, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: missing required token", ErrMissingConfig)
	}

	if cfg.TokenExchangeURL == "" {
		return nil, fmt.Errorf("%w: missing required token exchange url", ErrMissingConfig)
	}

	c := &TokenExchangeClient{
		tc:     &tokenCache{}, // cache set below.
		cfg:    cfg,
		tracer: noop.NewTracerProvider().Tracer("authn.TokenExchangeClient"),
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

	// If the options did not set the cache, create a new local cache.
	//
	// This has to be done this way because the cache that is created by
	// the cache.NewLocalCache function spawns a goroutine that cannot be
	// trivially stopped. It is set up to stop when the object is garbage
	// collected, but in the general case, the calling code will not have
	// control over that.
	if c.tc.cache == nil {
		c.tc.cache = cache.NewLocalCache(cache.Config{
			CleanupInterval: 5 * time.Minute,
		})
	}

	return c, nil

}

type TokenExchangeClient struct {
	tc         *tokenCache
	cfg        TokenExchangeConfig
	client     *http.Client
	tracer     trace.Tracer
	backoffCfg backoff.Config
}

type TokenExchangeRequest struct {
	// Namespace token should be signed with.
	// Use wildcard '*' to create a token for all namespaces.
	Namespace string `json:"namespace"`
	// Audiences token should be signed with.
	Audiences []string `json:"audiences"`
	// [Optional] SubjectToken is the token to exchange in case of a token exchange request.
	SubjectToken string `json:"subjectToken,omitempty"`
	// [Optional] Subject is a user identity to sign an on-behalf-of token for,
	// without first obtaining a signed subjectToken. It is mutually exclusive
	// with SubjectToken. The auth API requires the caller to hold the
	// grafana-id-token:sign scope (in addition to access-token:sign) to use it.
	Subject *TokenExchangeSubject `json:"subject,omitempty"`
	// [Optional] ExpiresIn is the duration, in seconds, before the token expires.
	ExpiresIn *int `json:"expiresIn,omitempty"`
	// [Optional] RestrictedDelegatedPermissions narrows the token's delegated permissions
	// to the intersection of this list and the CAP's delegated permissions. If omitted,
	// the full set of CAP delegated permissions is used.
	RestrictedDelegatedPermissions []string `json:"restrictedDelegatedPermissions,omitempty"`
}

// TokenExchangeSubject carries a user identity that the caller asserts when
// exchanging for an on-behalf-of access token. Its JSON shape matches the
// auth API's sign-access-token "subject" object and mirrors the claim set of
// an ID token.
type TokenExchangeSubject struct {
	// Sub is the fully-typed subject as it appears in the ID token's `sub`
	// claim (e.g. "user:1"). Its identifier part must be the numeric internal
	// ID, which downstream Grafana resolves via strconv.ParseInt. When empty
	// the auth API falls back to "<type>:<identifier>".
	Sub             string   `json:"sub,omitempty"`
	Identifier      string   `json:"identifier"`
	Type            string   `json:"type"`
	Namespace       string   `json:"namespace"`
	AuthenticatedBy string   `json:"authenticatedBy,omitempty"`
	Email           string   `json:"email,omitempty"`
	EmailVerified   bool     `json:"email_verified,omitempty"`
	Username        string   `json:"username,omitempty"`
	DisplayName     string   `json:"name,omitempty"`
	Role            string   `json:"role,omitempty"`
	Groups          []string `json:"groups,omitempty"`
}

type TokenExchangeResponse struct {
	Token string
}

func (r TokenExchangeRequest) hash() (string, error) {
	subjectKey, err := subjectCacheKey(r.Subject)
	if err != nil {
		return "", err
	}

	br := strings.Builder{}
	br.WriteString(r.Namespace)
	br.WriteByte('-')
	audiences := make([]string, len(r.Audiences))
	copy(audiences, r.Audiences)
	sort.Strings(audiences)
	br.WriteString(strings.Join(audiences, "-"))
	br.WriteString(subjectTokenCacheKey(r.SubjectToken))
	br.WriteString(subjectKey)
	br.WriteString(restrictedPermissionsCacheKey(r.RestrictedDelegatedPermissions))

	return br.String(), nil
}

func restrictedPermissionsCacheKey(permissions []string) string {
	if len(permissions) == 0 {
		return ""
	}

	sorted := make([]string, len(permissions))
	copy(sorted, permissions)
	sort.Strings(sorted)
	return "-" + strings.Join(sorted, "-")
}

type subjectTokenCacheClaims struct {
	jwt.Claims
	Actor *ActorClaims `json:"act,omitempty"`
}

func subjectTokenCacheKey(subjectToken string) string {
	if subjectToken == "" {
		return ""
	}

	parsed, err := jwt.ParseSigned(subjectToken, tokenSignAlgs)
	if err != nil {
		// Fall back to old behavior if the token cannot be parsed.
		return subjectToken
	}

	var claims subjectTokenCacheClaims
	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		// Fall back to old behavior if claims extraction fails.
		return subjectToken
	}

	parts := make([]string, 0, 4)
	if claims.Subject != "" {
		parts = append(parts, claims.Subject)
	}
	parts = append(parts, flattenedActorSubjects(claims.Actor)...)
	if len(parts) == 0 {
		// Fall back to old behavior if there is no stable subject signal.
		return subjectToken
	}

	return strings.Join(parts, "|")
}

func flattenedActorSubjects(actor *ActorClaims) []string {
	parts := make([]string, 0, 3)
	for actor != nil {
		if actor.Subject != "" {
			parts = append(parts, actor.Subject)
		}
		actor = actor.Actor
	}
	// Canonicalize to originator-first order (deepest actor first).
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

func subjectCacheKey(subject *TokenExchangeSubject) (string, error) {
	if subject == nil {
		return "", nil
	}

	s := *subject
	if len(s.Groups) > 0 {
		groups := make([]string, len(s.Groups))
		copy(groups, s.Groups)
		sort.Strings(groups)
		s.Groups = groups
	}

	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return "-" + string(data), nil
}

func (c *TokenExchangeClient) Exchange(ctx context.Context, r TokenExchangeRequest) (*TokenExchangeResponse, error) {
	ctx, span := c.tracer.Start(ctx, "authn.TokenExchangeClient.Exchange")
	defer span.End()

	if r.Namespace == "" {
		return nil, ErrMissingNamespace
	}

	if len(r.Audiences) == 0 {
		return nil, ErrMissingAudiences
	}

	if r.Subject != nil && r.SubjectToken != "" {
		return nil, ErrMutuallyExclusiveSubject
	}

	key, err := r.hash()
	if err != nil {
		return nil, fmt.Errorf("failed to build token exchange cache key: %w", err)
	}

	token, hit, err := c.tc.getOrFetch(ctx, key, func() (string, error) {
		data, err := json.Marshal(&r)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidExchangeResponse, err)
		}

		return postForToken(ctx, c.client, c.backoffCfg, span, c.cfg.TokenExchangeURL, c.cfg.Token, data, ErrInvalidExchangeResponse)
	})
	span.SetAttributes(attribute.Bool("cache_hit", hit))
	if err != nil {
		return nil, err
	}

	return &TokenExchangeResponse{Token: token}, nil
}

var _ TokenExchanger = StaticTokenExchanger{}

// NewStaticTokenExchanger Constructs a TokenExchanger that always returned provided token
func NewStaticTokenExchanger(token string) StaticTokenExchanger {
	return StaticTokenExchanger{token}
}

type StaticTokenExchanger struct {
	token string
}

func (s StaticTokenExchanger) Exchange(ctx context.Context, r TokenExchangeRequest) (*TokenExchangeResponse, error) {
	return &TokenExchangeResponse{Token: s.token}, nil
}
