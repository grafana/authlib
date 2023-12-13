package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/rbac-client-poc/src/cache"
	"github.com/grafana/rbac-client-poc/src/models"
)

type CacheWrap struct {
	successReadCnt  int
	successWriteCnt int
	cache           cache.Cache
}

// Get implements cache.Cache.
func (c *CacheWrap) Get(ctx context.Context, key string) (io.Reader, bool, error) {
	get, ok, err := c.cache.Get(ctx, key)
	if ok && err == nil {
		c.successReadCnt++
	}
	return get, ok, err
}

// Set implements cache.Cache.
func (c *CacheWrap) Set(ctx context.Context, key string, exp time.Duration, r io.Reader) error {
	err := c.cache.Set(ctx, key, exp, r)
	if err == nil {
		c.successWriteCnt++
	}
	return err
}

func TestRBACClientImpl_SearchUserPermissions(t *testing.T) {
	perms := map[string][]string{
		"users:read": {"org.users:*"},
		"teams:read": {"teams:id:1", "teams:id:2"},
	}
	tests := []struct {
		name    string
		query   SearchQuery
		want    models.Permissions
		wantErr bool
	}{
		{
			name:  "userID 1 no error",
			query: SearchQuery{Action: "users:read", UserID: 1},
			want:  models.Permissions{"users:read": {"org.users:*"}},
		},
	}
	for _, tt := range tests {
		testCache := &CacheWrap{cache: cache.NewLocalCache()}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d := []byte{}
			if tt.query.Action != "" {
				d, _ = json.Marshal(map[string][]string{tt.query.Action: perms[tt.query.Action]})
			}
			require.Equal(t, r.Header.Get("Authorization"), "Bearer aabbcc")
			require.Equal(t, r.URL.String(), fmt.Sprintf(searchPath, tt.query.UserID))
			w.Write(d)
		}))
		defer server.Close()
		t.Run(tt.name, func(t *testing.T) {
			c := NewRBACClient(ClientCfg{
				Timeout:    time.Minute,
				GrafanaURL: server.URL,
				Token:      "aabbcc",
			}, testCache)
			c.client = server.Client()

			got, err := c.SearchUserPermissions(context.Background(), tt.query)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)

			require.Equal(t, 1, testCache.successWriteCnt)

			// Should read from cache
			got2, err := c.SearchUserPermissions(context.Background(), tt.query)
			require.NoError(t, err)
			require.Equal(t, tt.want, got2)

			require.Equal(t, 1, testCache.successReadCnt)
		})
	}
}
