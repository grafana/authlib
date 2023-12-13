package models

// Permissions maps actions to the scopes they can be applied to.
// ex: { "pluginID.users:read": ["pluginID.users:uid:xHuuebS", "pluginID.users:uid:znbGGd"] }
type Permissions map[string][]string

// Checker checks whether a user has access to any of the provided scopes.
type Checker func(scopes ...string) bool
