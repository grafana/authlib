package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/dskit/backoff"
)

// authAPIResponse is the {data:{token},status,error} response shape shared by every auth-api
// token-minting endpoint (sign-access-token, exchange, derive-id-token).
type authAPIResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

// postForToken posts body to url as a bearer-authenticated auth-api request, retrying on network
// errors, 429s, and 5xxs per backoffCfg, and decodes the shared authAPIResponse. errInvalid
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

	response := authAPIResponse{}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("%w: %w", errInvalid, err)
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
