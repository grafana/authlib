package authnv1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestAuthenticateRequestOAuthPassthroughOptIn(t *testing.T) {
	t.Run("defaults to false when omitted", func(t *testing.T) {
		var req AuthenticateRequest
		require.NoError(t, protojson.Unmarshal([]byte(`{"namespace":"stacks-1"}`), &req))
		assert.False(t, req.GetIncludeOauthPassthroughHeaders())
	})

	t.Run("accepts an explicit opt in", func(t *testing.T) {
		var req AuthenticateRequest
		require.NoError(t, protojson.Unmarshal([]byte(`{"includeOauthPassthroughHeaders":true}`), &req))
		assert.True(t, req.GetIncludeOauthPassthroughHeaders())
	})
}
