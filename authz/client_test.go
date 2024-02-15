package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/internal/cache"
)

func TestRBACClientImpl_SearchUserPermissions(t *testing.T) {
	perms := map[string][]string{
		"users:read": {"org.users:*"},
		"teams:read": {"teams:id:1", "teams:id:2"},
	}
	tests := []struct {
		name    string
		query   SearchQuery
		want    SearchResponse
		wantErr bool
	}{
		{
			name:  "NamespaceID user:1 no error",
			query: SearchQuery{Action: "users:read", NamespaceID: "user:1"},
			want: SearchResponse{
				Data: &PermissionsByID{1: {"users:read": {"org.users:*"}}},
			},
		},
	}
	for _, tt := range tests {
		testCache := &cacheWrap{cache: cache.NewLocalCache(cache.Config{Expiry: 10 * time.Minute, CleanupInterval: 10 * time.Minute})}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d := []byte{}
			if tt.query.Action != "" {
				// Using a string instead of an int on purpose as this is what is returned by the API.
				d, _ = json.Marshal(map[string]map[string][]string{fmt.Sprintf("%v", strings.Split(tt.query.NamespaceID, ":")[1]): {tt.query.Action: perms[tt.query.Action]}})
			}
			require.Equal(t, r.Header.Get("Authorization"), "Bearer aabbcc")
			require.Equal(t, r.URL.Path, searchPath)
			_, _ = w.Write(d)

		}))
		defer server.Close()
		t.Run(tt.name, func(t *testing.T) {
			c, err := newClient(Config{
				APIURL: server.URL,
				Token:  "aabbcc",
			}, withCache(testCache))
			require.NoError(t, err)

			c.client = server.Client()

			got, err := c.Search(context.Background(), tt.query)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.want, *got)

			require.Equal(t, 1, testCache.successWriteCnt)

			// Should read from cache
			got2, err := c.Search(context.Background(), tt.query)
			require.NoError(t, err)
			require.NotNil(t, got2)
			require.Equal(t, tt.want, *got2)

			require.Equal(t, 1, testCache.successReadCnt)
		})
	}
}
