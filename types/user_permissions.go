package types

import (
	"context"
	"time"
)

type Permission struct {
	Action string
	Scope  string
}

type GetUserPermissionsRequest struct {
	Namespace string
	SkipCache bool
}

type GetUserPermissionsResponse struct {
	Permissions []Permission
	CacheUntil  time.Time
}

type UserPermissionsClient interface {
	GetUserPermissions(ctx context.Context, info AuthInfo, req GetUserPermissionsRequest) (GetUserPermissionsResponse, error)
	InvalidateUserPermissions(ctx context.Context, info AuthInfo, req GetUserPermissionsRequest) error
}
