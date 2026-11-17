package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTokenExchangeClientCachesByRequestedLifetime(t *testing.T) {
	ptr := func(value int) *int { return &value }
	for _, mode := range []string{"service", "subject token", "subject"} {
		t.Run(mode, func(t *testing.T) {
			// Each response has its own signature, including default vs explicit 300.
			tokens := map[string]string{}
			for value, seconds := range map[string]int{"default": 300, "60": 60, "300": 300, "900": 900} {
				tokens[value] = signAccessToken(t, time.Duration(seconds)*time.Second)
			}
			calls := make(chan TokenExchangeRequest, 20)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request TokenExchangeRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				calls <- request
				key := "default"
				if request.ExpiresIn != nil {
					switch *request.ExpiresIn {
					case 60:
						key = "60"
					case 300:
						key = "300"
					case 900:
						key = "900"
					default:
						http.Error(w, "invalid lifetime", http.StatusForbidden)
						return
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"token": tokens[key]}})
			}))
			t.Cleanup(server.Close)
			client, err := NewTokenExchangeClient(TokenExchangeConfig{Token: "test-token", TokenExchangeURL: server.URL})
			require.NoError(t, err)
			request := TokenExchangeRequest{Namespace: "default", Audiences: []string{"grafana"}}
			switch mode {
			case "subject token":
				request.SubjectToken = signSubjectToken(t, time.Hour, "user:1", nil)
			case "subject":
				request.Subject = &TokenExchangeSubject{Sub: "user:1", Identifier: "uid-1", Type: "user", Namespace: "default"}
			}
			for _, step := range []struct {
				requested *int
				key       string
				cached    bool
			}{
				{nil, "default", false}, {ptr(60), "60", false}, {ptr(900), "900", false}, {ptr(300), "300", false},
				{ptr(60), "60", true}, {nil, "default", true}, {ptr(300), "300", true}, {ptr(900), "900", true},
				{ptr(0), "", false}, {ptr(-1), "", false}, {ptr(int(^uint(0) >> 1)), "", false},
				{ptr(0), "", false}, {nil, "default", true},
			} {
				request.ExpiresIn = step.requested
				response, err := client.Exchange(t.Context(), request)
				if step.key == "" {
					require.ErrorIs(t, err, ErrInvalidExchangeResponse)
					require.Nil(t, response)
				} else {
					require.NoError(t, err)
					require.Equal(t, tokens[step.key], response.Token)
				}
				if step.cached {
					require.Empty(t, calls, "identical request should use cached token")
				} else {
					require.Len(t, calls, 1, "different lifetime must reach the server, including invalid requests")
					got := <-calls
					require.Equal(t, step.requested, got.ExpiresIn)
				}
			}
		})
	}
}
