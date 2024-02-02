package models

// UsersPermissions groups permissions (with scopes grouped by action) by User ID.
// ex: { 1: { "teams:read": ["teams:id:2", "teams:id:3"] }, 3: { "teams:read": ["teams:id:1", "teams:id:3"] } }
type UsersPermissions map[int64]Permissions

// Permissions maps actions to the scopes they can be applied to.
// ex: { "pluginID.users:read": ["pluginID.users:uid:xHuuebS", "pluginID.users:uid:znbGGd"] }
type Permissions map[string][]string

// Checker checks whether a user has access to any of the provided scopes.
type Checker func(scopes ...string) bool
