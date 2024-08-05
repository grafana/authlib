package claims

import "time"

type AuthInfo interface {
	Identity() IdentityClaims
	Access() AccessClaims
}

type TokenClaims interface {
	Issuer() string
	Subject() string
	Audience() []string
	Expiry() *time.Time
	NotBefore() *time.Time
	IssuedAt() *time.Time

	// ID for the claims (not the identity!)
	ID() string

	// Namespace takes the form of '<type>-<id>', '*' means all namespaces.
	// In grafana the can be either org or stack.
	// The claims are valid within this namespace
	Namespace() string
}

type IdentityClaims interface {
	TokenClaims

	// UID is the unique ID of the user (UID attribute)
	// This will often be the string version of a TypedID `<type>:<id>`
	UID() string

	// AuthenticatedBy is the method used to authenticate the identity.
	AuthenticatedBy() string
	Email() string
	EmailVerified() bool

	// Username of the user (login attribute on the Identity)
	Username() string

	// Display Name of the user (name attribute if it is set, otherwise the login or email)
	DisplayName() string
}

type AccessClaims interface {
	TokenClaims

	// Access policy scopes
	Scopes() []string
	// Grafana roles
	Permissions() []string
	// On-behalf-of user
	DelegatedPermissions() []string
}
