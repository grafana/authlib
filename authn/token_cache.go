package authn

import (
	"bytes"
	"context"
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
	"golang.org/x/sync/singleflight"

	"github.com/grafana/authlib/cache"
	"github.com/grafana/dskit/backoff"
)

// authAPIEnvelope is the {data:{token},status,error} response shape shared by every auth-api
// token-minting endpoint (sign-access-token, exchange, derive-id-token).
type authAPIEnvelope struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

// tokenCache mints and caches short-lived bearer tokens from auth-api, keyed by an opaque cache
// key the caller derives from its own request shape. Concurrent calls for the same key are
// coalesced via singleflight, and cache TTL is taken from each minted token's own JWT expiry.
// Shared by every auth-api token client in this package so the retry/backoff/cache plumbing is
// written once instead of once per capability (exchange, derive, ...).
type tokenCache struct {
	cache   cache.Cache
	singlef singleflight.Group
}

// getOrFetch returns the cached token for key, or calls fetch to mint one and caches it (best
// effort) under key before returning. hit reports whether the value came from cache, for callers
// that want to record it on their span.
func (t *tokenCache) getOrFetch(ctx context.Context, key string, fetch func() (string, error)) (token string, hit bool, err error) {
	if token, ok := t.get(ctx, key); ok {
		return token, true, nil
	}

	v, err, _ := t.singlef.Do(key, func() (interface{}, error) {
		token, err := fetch()
		if err != nil {
			return nil, err
		}
		// A valid token was already minted, so a caching failure shouldn't fail the call.
		_ = t.set(ctx, key, token)
		return token, nil
	})
	if err != nil {
		return "", false, err
	}
	return v.(string), false, nil
}

func (t *tokenCache) get(ctx context.Context, key string) (string, bool) {
	if token, err := t.cache.Get(ctx, key); err == nil {
		return string(token), true
	}
	return "", false
}

func (t *tokenCache) set(ctx context.Context, key, token string) error {
	const cacheLeeway = 15 * time.Second

	parsed, err := jwt.ParseSigned(token, tokenSignAlgs)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	var claims jwt.Claims
	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return fmt.Errorf("failed to extract claims from the token: %w", err)
	}

	return t.cache.Set(ctx, key, []byte(token), time.Until(claims.Expiry.Time())-cacheLeeway)
}

// postForToken posts body to url as a bearer-authenticated auth-api request, retrying on network
// errors, 429s, and 5xxs per backoffCfg, and decodes the shared authAPIEnvelope response. errInvalid
// is wrapped around any protocol-level failure so each caller can errors.Is against its own
// capability-specific sentinel while sharing this retry/decode loop.
func postForToken(ctx context.Context, httpClient *http.Client, backoffCfg backoff.Config, span trace.Span, url, bearerToken string, body []byte, errInvalid error) (string, error) {
	b := backoff.New(ctx, backoffCfg)

	var req *http.Request
	var res *http.Response
	var err error
	for b.Ongoing() {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return "", fmt.Errorf("failed to build http request: %w", err)
		}

		res, err = httpClient.Do(withAuthAPIHeaders(req, bearerToken))
		addResponseInformationToSpan(span, res, err)
		// Retry the request if there was a fundamental error, like resolving the host or network error,
		// or if we get a 429 or a 500s HTTP status code.
		if shouldRetry(res, err) {
			// Consume and close response body after each attempt, so connections can be reused.
			if res != nil {
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}

			b.Wait()
			continue
		}

		defer func() { _ = res.Body.Close() }()

		// No error, exit the retry loop.
		break
	}

	if err != nil || b.Err() != nil {
		// If we get here, it means we had hit the MaxRetries limit or an error happened
		// while retrying the request (for example, context canceled).
		return "", fmt.Errorf("%w: %w", errInvalid, errors.Join(b.Err(), err))
	}

	if res.StatusCode >= http.StatusInternalServerError {
		return "", fmt.Errorf("%w: %s", errInvalid, res.Status)
	}

	response := authAPIEnvelope{}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		if response.Error != "" {
			return "", fmt.Errorf("%w: %s", errInvalid, response.Error)
		}
		return "", fmt.Errorf("%w: %s", errInvalid, res.Status)
	}

	return response.Data.Token, nil
}

// shouldRetry determines whether a request should be retried based on the HTTP response status code
// or the presence of an error. It returns true for HTTP 429 (Too Many Requests) or server errors
// (HTTP status codes 500 and above).
func shouldRetry(res *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if res != nil {
		return res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= http.StatusInternalServerError
	}
	return false
}

// addResponseInformationToSpan adds an event to the span indicating error and HTTP status code.
func addResponseInformationToSpan(span trace.Span, res *http.Response, err error) {
	if err != nil {
		span.RecordError(err)
	} else {
		span.AddEvent("response", trace.WithAttributes(attribute.Int("status", res.StatusCode)))
	}
}

func withAuthAPIHeaders(r *http.Request, bearerToken string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+bearerToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "authlib-client")

	// Always propagate system token headers.
	// These will be ignored for non system tokens.
	r.Header.Set("X-Org-ID", "0")
	r.Header.Set("X-Realms", `[{"type": "system", "identifier": "system"}]`)

	// Propagate OpenTelemetry context headers.
	otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))

	return r
}
