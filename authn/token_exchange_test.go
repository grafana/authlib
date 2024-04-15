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
	testToken := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImlkLXNpZ25pbmcta2V5IiwidHlwIjoiYXQrand0In0.eyJhdWQiOiJvcmc6MSIsImV4cCI6MTcxMjg0MzM3MCwiaWF0IjoxNzEyODQyNzcwLCJpc3MiOiJjMDU4MWRiNy1hNWNjLTQ0NzYtYWQ5YS00NmZmMmE3M2M2MzAiLCJqdGkiOiI0YWM3NGRlNi00MzZlLTQwZDItOWRkZi05MDJhY2I1MjkxYzciLCJvcmdfaWQiOiIxIiwic3ViIjoiYWNjZXNzLXBvbGljeTpjMDU4MWRiNy1hNWNjLTQ0NzYtYWQ5YS00NmZmMmE3M2M2MzAifQ.DezKTVvy__TFyI7cJXHYubK5vuCp8RIst1Ce-Cgrl5k9U3aCP6NvoaMywP_YVHb_Xar-wHP2aoJ1jct80oiofA"
	tests := []struct {
		name     string
		request  TokenExchangeRequest
		response string
		want     string
		wantErr  bool
	}{
		{
			name:    "Error if realm and org ID are not provided for a system wide CAP token",
			request: TokenExchangeRequest{},
			want:    "",
			wantErr: true,
		},
		{
			name: "Can parse a successful response",
			request: TokenExchangeRequest{
				Realms: []Realm{
					{
						Type:       "org",
						Identifier: "1",
					},
				},
				OrgID: 1,
			},
			response: fmt.Sprintf(`{"status":"success","data":{"token":"%s"}}`, testToken),
			want:     testToken,
			wantErr:  false,
		},
		{
			name: "Can parse an error response",
			request: TokenExchangeRequest{
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
			c, err := NewSystemTokenExchangeClient(TokenExchangeConfig{
				AuthAPIURL: server.URL,
				CAPToken:   capToken,
			}, WithHTTPClient(server.Client()))
			require.NoError(t, err)

			token, err := c.ExchangeSystemToken(context.Background(), tt.request)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, token)
		})
	}
}
