package authz

import (
	"bytes"
	"context"
	"encoding/gob"

	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/types"
)

func userPermissionsCacheKey(subject string, teams []string, namespace string) string {
	return authorizationCacheKey("user-permissions", namespace, subject, teamsCacheKey(teams))
}

func (c *ClientImpl) getCachedUserPermissions(ctx context.Context, key string) (types.GetUserPermissionsResponse, error) {
	data, err := c.cache.Get(ctx, key)
	if err != nil {
		return types.GetUserPermissionsResponse{}, err
	}

	var response types.GetUserPermissionsResponse
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&response); err != nil {
		return types.GetUserPermissionsResponse{}, err
	}
	return response, nil
}

func (c *ClientImpl) cacheUserPermissions(ctx context.Context, key string, response types.GetUserPermissionsResponse) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}
