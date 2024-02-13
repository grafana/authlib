package authz

type Response[T any] struct {
	Data  *T     `json:"data"`
	Error string `json:"error"`
}

// Permissions maps actions to the scopes they can be applied to.
// ex: { "pluginID.users:read": ["pluginID.users:uid:xHuuebS", "pluginID.users:uid:znbGGd"] }
type Permissions map[string][]string

// Resource represents a resource in Grafana.
type Resource struct {
	// Kind is the type of resource. Ex: "teams", "dashboards", "datasources"
	Kind string
	// The attribute is required for compatibility with the way scopes are defined in Grafana. Ex: "id", "uid"
	Attr string
	// ID is the unique identifier of the resource. Ex: "2", "YYxUSd7ik", "test-datasource"
	ID string
}

func (r *Resource) Scope() string {
	return r.Kind + ":" + r.Attr + ":" + r.ID
}

func (r *Resource) ScopePrefix() string {
	return r.Kind + ":" + r.Attr + ":"
}
