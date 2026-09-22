package authn

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/grafana/authlib/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCacheExpiration(t *testing.T) {
	for _, tt := range []struct {
		name      string
		elapsed   time.Duration
		wantCache bool
	}{
		{name: "normal lifetime", wantCache: true},
		{name: "just above margin", elapsed: 15*time.Second - time.Nanosecond, wantCache: true},
		{name: "at margin", elapsed: 15 * time.Second},
		{name: "just below margin", elapsed: 15*time.Second + time.Nanosecond},
		{name: "short remaining lifetime", elapsed: 20 * time.Second},
		{name: "expired", elapsed: 31 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Keep the default cache expiration semantics without a background janitor.
				tc := &tokenCache{cache: cache.NewLocalCache(cache.Config{})}
				token := signAccessToken(t, 30*time.Second)
				time.Sleep(tt.elapsed)

				ctx := context.Background()
				require.NoError(t, tc.set(ctx, "token", token))
				got, ok := tc.get(ctx, "token")
				assert.Equal(t, tt.wantCache, ok)
				if tt.wantCache {
					assert.Equal(t, token, got)
					// Advance past the cache deadline, while the JWT is still valid.
					time.Sleep(15*time.Second - tt.elapsed + time.Nanosecond)
					_, ok = tc.get(ctx, "token")
					assert.False(t, ok)
				}
			})
		})
	}
}
