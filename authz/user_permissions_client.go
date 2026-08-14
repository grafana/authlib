package authz

import (
	"context"
	"errors"
	"fmt"
	"io"

	"go.opentelemetry.io/otel/attribute"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"
)

var (
	ErrInvalidUserPermissionsResponse = errors.New("invalid user permissions response")
	ErrUserPermissionsDenied          = errors.New("user permissions request denied")
)

var _ types.UserPermissionsClient = (*ClientImpl)(nil)

func (c *ClientImpl) InvalidateUserPermissions(ctx context.Context, authInfo types.AuthInfo, req types.GetUserPermissionsRequest) error {
	if authInfo.GetSubject() == "" {
		return ErrMissingAuthInfo
	}
	if !types.NamespaceMatches(authInfo.GetNamespace(), req.Namespace) {
		return namespaceMismatchError(authInfo.GetNamespace(), req.Namespace)
	}
	key := userPermissionsCacheKey(authInfo.GetUID(), authInfo.GetGroups(), req.Namespace)
	return c.cache.Delete(ctx, key)
}

func (c *ClientImpl) GetUserPermissions(ctx context.Context, authInfo types.AuthInfo, req types.GetUserPermissionsRequest) (types.GetUserPermissionsResponse, error) {
	ctx, span := c.tracer.Start(ctx, "ClientImpl.GetUserPermissions")
	defer span.End()

	if authInfo.GetSubject() == "" {
		span.RecordError(ErrMissingAuthInfo)
		return types.GetUserPermissionsResponse{}, ErrMissingAuthInfo
	}
	if !types.NamespaceMatches(authInfo.GetNamespace(), req.Namespace) {
		return types.GetUserPermissionsResponse{}, namespaceMismatchError(authInfo.GetNamespace(), req.Namespace)
	}
	servicePermission := CheckServicePermissions(authInfo, "authz.grafana.app", "userpermissions", "get")
	if !servicePermission.Allowed {
		return types.GetUserPermissionsResponse{}, ErrUserPermissionsDenied
	}
	key := userPermissionsCacheKey(authInfo.GetUID(), authInfo.GetGroups(), req.Namespace)
	if !req.SkipCache {
		if cached, err := c.getCachedUserPermissions(ctx, key); err == nil {
			return cached, nil
		}
	}

	span.SetAttributes(
		attribute.String("subject", authInfo.GetSubject()),
		attribute.String("namespace", req.Namespace),
	)

	stream, err := c.clientV1.GetUserPermissions(newOutgoingContext(ctx), &authzv1.GetUserPermissionsRequest{
		Subject:   authInfo.GetUID(),
		Namespace: req.Namespace,
		Teams:     authInfo.GetGroups(),
		Options:   &authzv1.GetUserPermissionsOptions{Skipcache: req.SkipCache},
	})
	if err != nil {
		span.RecordError(err)
		return types.GetUserPermissionsResponse{}, err
	}

	var result types.GetUserPermissionsResponse
	receivedChunk := false
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			span.RecordError(err)
			return types.GetUserPermissionsResponse{}, err
		}
		receivedChunk = true

		for _, permission := range chunk.Permissions {
			if permission == nil {
				return types.GetUserPermissionsResponse{}, fmt.Errorf("%w: nil permission", ErrInvalidUserPermissionsResponse)
			}
			result.Permissions = append(result.Permissions, types.Permission{
				Action: permission.Action,
				Scope:  permission.Scope,
			})
		}
	}

	if !receivedChunk {
		return types.GetUserPermissionsResponse{}, fmt.Errorf("%w: empty stream", ErrInvalidUserPermissionsResponse)
	}

	if err := c.cacheUserPermissions(ctx, key, result); err != nil {
		span.RecordError(err)
		span.AddEvent("failed to cache user permissions")
	}

	span.SetAttributes(attribute.Int("permissions", len(result.Permissions)))
	return result, nil
}
