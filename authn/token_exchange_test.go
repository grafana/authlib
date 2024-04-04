package authn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_TokenExchangeClient(t *testing.T) {
	tests := []struct {
		name     string
		request  AccessTokenRequest
		response string
		want     string
		wantErr  bool
	}{
		{
			name:    "Error if realm and org ID are not provided for a system wide CAP",
			request: AccessTokenRequest{},
			want:    "",
			wantErr: true,
		},
		{
			name: "Can parse a successful response",
			request: AccessTokenRequest{
				Realms: []Realm{
					{
						Type:       "org",
						Identifier: "1",
					},
				},
				OrgID: 1,
			},
			response: `{"status":"success","data":{"token":"exchanged_token"}}`,
			want:     "exchanged_token",
			wantErr:  false,
		},
		{
			name: "Can parse an error response",
			request: AccessTokenRequest{
				Realms: []Realm{
					{
						Type:       "org",
						Identifier: "1",
					},
				},
				OrgID: 1,
			},
			response: `{"status":"error","error":"invalid permission"}`,
			want:     "",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		capToken := "glcd_eyJvIjoiMCIsIm4iOiJ0b2tlbl8xIiwiayI6Ik84RTREMmU3Rk9DNmhQMXBRMHRqOEswNCIsIm0iOnsiciI6ImRldi11cyJ9fQ=="
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

			token, err := c.GetAccessToken(context.Background(), tt.request)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, token)
		})
	}
}
