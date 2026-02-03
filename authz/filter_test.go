package authz

import (
	"context"
	"strconv"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"
)

// testItem is a simple item type for testing
type testItem struct {
	name      string
	folder    string
	namespace string
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
		Namespace: item.namespace,
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
		{name: "item-0", folder: "folder1", namespace: "default"},
		{name: "item-1", folder: "folder1", namespace: "default"},
		{name: "item-2", folder: "folder1", namespace: "default"},
	}

	var authorizedItems []string
	for item, err := range FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(items), extractTestItem) {
		require.NoError(t, err)
		authorizedItems = append(authorizedItems, item.name)
	}

	assert.Equal(t, []string{"item-0", "item-1", "item-2"}, authorizedItems)
}

func TestFilterAuthorized_AllDenied(t *testing.T) {
	items := []testItem{
		{name: "item-0", folder: "folder1", namespace: "default"},
		{name: "item-1", folder: "folder1", namespace: "default"},
		{name: "item-2", folder: "folder1", namespace: "default"},
	}

	count := 0
	for _, err := range FilterAuthorized(ctxWithUser(), types.FixedAccessClient(false), toSeq(items), extractTestItem) {
		require.NoError(t, err)
		count++
	}

	assert.Equal(t, 0, count)
}

func TestFilterAuthorized_MissingAuthInfo(t *testing.T) {
	items := []testItem{
		{name: "item-0", folder: "folder1", namespace: "default"},
	}

	// Use context without auth info
	var gotError error
	for _, err := range FilterAuthorized(context.Background(), types.FixedAccessClient(true), toSeq(items), extractTestItem) {
		if err != nil {
			gotError = err
			break
		}
	}

	assert.Error(t, gotError)
	assert.Contains(t, gotError.Error(), "missing auth info")
}

func TestFilterAuthorized_EmptyInput(t *testing.T) {
	count := 0
	for range FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(nil), extractTestItem) {
		count++
	}

	assert.Equal(t, 0, count)
}

func TestFilterAuthorized_EarlyTermination(t *testing.T) {
	items := []testItem{
		{name: "item-0", folder: "folder1", namespace: "default"},
		{name: "item-1", folder: "folder1", namespace: "default"},
		{name: "item-2", folder: "folder1", namespace: "default"},
	}

	// Only take first item
	count := 0
	for range FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(items), extractTestItem) {
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
		items[i] = testItem{name: "item-" + strconv.Itoa(i), folder: "folder1", namespace: "default"}
	}

	count := 0
	for _, err := range FilterAuthorized(ctxWithUser(), types.FixedAccessClient(true), toSeq(items), extractTestItem) {
		require.NoError(t, err)
		count++
	}

	assert.Equal(t, len(items), count)
}

func TestFilterAuthorized_NamespaceSwitch(t *testing.T) {
	// Items with alternating namespaces should trigger batch flushes
	items := []testItem{
		{name: "item-0", folder: "folder1", namespace: "ns1"},
		{name: "item-1", folder: "folder1", namespace: "ns1"},
		{name: "item-2", folder: "folder1", namespace: "ns2"}, // namespace change
		{name: "item-3", folder: "folder1", namespace: "ns2"},
		{name: "item-4", folder: "folder1", namespace: "ns3"}, // namespace change back
	}

	client, fakeClient := setupAccessClient()
	fakeClient.checkRes = &authzv1.CheckResponse{Allowed: true}

	// Use IDTokenAuthInfo to create a user identity that goes through authz
	// (AccessTokenAuthInfo creates access policy type which bypasses authz)
	authInfo := authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "access-policy"},
			Rest: authn.AccessTokenClaims{
				Namespace:            "*",
				DelegatedPermissions: []string{"test.grafana.app/items:get"},
			},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest:   authn.IDTokenClaims{Namespace: "*"},
		},
	)
	ctx := types.WithAuthInfo(context.Background(), authInfo)

	var authorizedItems []string
	for item, err := range FilterAuthorized(ctx, client, toSeq(items), extractTestItem) {
		require.NoError(t, err)
		authorizedItems = append(authorizedItems, item.name)
	}

	// All items should be authorized
	assert.Equal(t, []string{"item-0", "item-1", "item-2", "item-3", "item-4"}, authorizedItems)

	// Should have 3 batch calls due to namespace changes
	require.Len(t, fakeClient.batchCheckReqs, 3)

	// First batch: ns1 with 2 items
	assert.Len(t, fakeClient.batchCheckReqs[0].Checks, 2)
	assert.Equal(t, "ns1", fakeClient.batchCheckReqs[0].Namespace)

	// Second batch: ns2 with 2 items
	assert.Len(t, fakeClient.batchCheckReqs[1].Checks, 2)
	assert.Equal(t, "ns2", fakeClient.batchCheckReqs[1].Namespace)

	// Third batch: ns3 with 1 item
	assert.Len(t, fakeClient.batchCheckReqs[2].Checks, 1)
	assert.Equal(t, "ns3", fakeClient.batchCheckReqs[2].Namespace)
}
