package authn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientImpl_Search(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
		wantErr  bool
	}{
		{
			name:     "Can parse a successful response",
			response: `{"status":"success","data":{"token":"exchanged_token"}}`,
			want:     "exchanged_token",
			wantErr:  false,
		},
		{
			name:     "Can parse an error response",
			response: `{"status":"error","error":"invalid permission"}`,
			want:     "",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		capToken := "test_cap_token"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.Header.Get("Authorization"), fmt.Sprintf("Bearer %s", capToken))
			require.Equal(t, r.URL.Path, tokenExchangePath)
			_, _ = w.Write([]byte(tt.response))

		}))
		defer server.Close()
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewTokenExchangeClient(Config{
				AuthAPIURL: server.URL,
				CAP:        capToken,
			})
			require.NoError(t, err)

			c.client = server.Client()

			token, err := c.GetAccessToken(context.Background(), AccessTokenRequest{})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, token)
		})
	}
}
