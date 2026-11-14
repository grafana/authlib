package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTypeID(t *testing.T) {
	t.Run("plugin", func(t *testing.T) {
		typ, id, err := ParseTypeID(NewTypeID(TypePlugin, "grafana-example-app"))
		require.NoError(t, err)
		assert.Equal(t, TypePlugin, typ)
		assert.Equal(t, "grafana-example-app", id)
	})

	t.Run("access policy", func(t *testing.T) {
		typ, id, err := ParseTypeID("access-policy:abc")
		require.NoError(t, err)
		assert.Equal(t, TypeAccessPolicy, typ)
		assert.Equal(t, "abc", id)
	})

	t.Run("unknown type", func(t *testing.T) {
		_, _, err := ParseTypeID("unknown:abc")
		require.ErrorIs(t, err, ErrInvalidTypedID)
	})
}
