package authz

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/types"
)

// testItem is a simple item type for testing
type testItem struct {
	name   string
	folder string
}

// ctxWithUser returns a context with auth info embedded
func ctxWithUser() context.Context {
	authInfo := authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
		Claims: jwt.Claims{Subject: "user:1"},
		Rest: authn.AccessTokenClaims{
			Namespace:   "default",
			Permissions: []string{"test.grafana.app/items:get"},
		},
	})
	return types.WithAuthInfo(context.Background(), authInfo)
}

// extractTestItem is a helper to create BatchCheckItem from testItem
func extractTestItem(item testItem) BatchCheckItem {
	return BatchCheckItem{
		Name:      item.name,
		Folder:    item.folder,
		Verb:      "get",
		Group:     "test.grafana.app",
		Resource:  "items",
		Namespace: "default",
	}
}

// toSeq converts a slice to an iter.Seq
func toSeq(items []testItem) func(yield func(testItem) bool) {
	return func(yield func(testItem) bool) {
		for _, item := range items {
			if !yield(item) {
				return
			}
		}
	}
}

func TestFilterAuthorized_AllAllowed(t *testing.T) {
	items := []testItem{
		{name: "item-0", folder: "folder1"},
		{name: "item-1", folder: "folder1"},
		{name: "item-2", folder: "folder1"},
	}

	result := FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(items), extractTestItem)

	var authorizedItems []string
	for item, err := range result.Items {
		require.NoError(t, err)
		authorizedItems = append(authorizedItems, item.name)
	}

	assert.Equal(t, []string{"item-0", "item-1", "item-2"}, authorizedItems)
	assert.NotNil(t, result.Zookie)
}

func TestFilterAuthorized_AllDenied(t *testing.T) {
	items := []testItem{
		{name: "item-0", folder: "folder1"},
		{name: "item-1", folder: "folder1"},
		{name: "item-2", folder: "folder1"},
	}

	result := FilterAuthorized(ctxWithUser(), types.FixedAccessClient(false), toSeq(items), extractTestItem)

	count := 0
	for _, err := range result.Items {
		require.NoError(t, err)
		count++
	}

	assert.Equal(t, 0, count)
	assert.NotNil(t, result.Zookie)
}

func TestFilterAuthorized_MissingAuthInfo(t *testing.T) {
	items := []testItem{
		{name: "item-0", folder: "folder1"},
	}

	result := FilterAuthorized(context.Background(), types.FixedAccessClient(true), toSeq(items), extractTestItem)

	// Use context without auth info
	var gotError error
	for _, err := range result.Items {
		if err != nil {
			gotError = err
			break
		}
	}

	assert.Error(t, gotError)
	assert.Contains(t, gotError.Error(), "missing auth info")
}

func TestFilterAuthorized_EmptyInput(t *testing.T) {
	result := FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(nil), extractTestItem)

	count := 0
	for range result.Items {
		count++
	}

	assert.Equal(t, 0, count)
}

func TestFilterAuthorized_ZookiePopulated(t *testing.T) {
	items := []testItem{
		{name: "item-0", folder: "folder1"},
	}

	result := FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(items), extractTestItem)

	// Zookie pointer should be set
	assert.NotNil(t, result.Zookie)

	// Consume the iterator
	for range result.Items {
	}

	// Zookie should be populated after iteration (FixedAccessClient returns NoopZookie)
	assert.NotNil(t, result.Zookie)
}

func TestFilterAuthorized_EarlyTermination(t *testing.T) {
	items := []testItem{
		{name: "item-0", folder: "folder1"},
		{name: "item-1", folder: "folder1"},
		{name: "item-2", folder: "folder1"},
	}

	result := FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(items), extractTestItem)

	// Only take first item
	count := 0
	for range result.Items {
		count++
		if count >= 1 {
			break
		}
	}

	assert.Equal(t, 1, count)
}

func TestFilterAuthorized_LargeBatch(t *testing.T) {
	// Create more items than MaxBatchCheckItems to test batching
	items := make([]testItem, types.MaxBatchCheckItems+10)
	for i := range items {
		items[i] = testItem{name: "item-" + string(rune('0'+i%10)), folder: "folder1"}
	}

	result := FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(items), extractTestItem)

	count := 0
	for _, err := range result.Items {
		require.NoError(t, err)
		count++
	}

	assert.Equal(t, len(items), count)
}
