package claims

// AuthInfo provides access to the requested authnz info
// This includes the identity and access claims.  This interface is also designed to
// fulfil the kubernetes user requirements:
// https://github.com/kubernetes/apiserver/blob/master/pkg/authentication/user/user.go#L20
type AuthInfo interface {
	// GetName returns the name that can be shown to identify the identity
	// This may be a configured display name, an email, or (worst case) a ID
	GetName() string

	// GetUID returns a unique value for a particular identity that will change
	// if the user is removed from the system and another user is added with
	// the same name.
	// This will be in the form: <IdentityType>:<Identifier>
	GetUID() string

	// GetIdentifier returns only the Identitfier part.
	// For some identity types this can be empty e.g. Anonymous.
	GetIdentifier() string

	// GetIdentityType return the identity type.
	GetIdentityType() IdentityType

	// GetNamespace returns a namespace in the form of '<type>-<id>', '*' means all namespaces.
	// In Grafana the can be either org or stacks.
	GetNamespace() string

	// GetGroups returns the names of the groups the identity is a member of
	// This is unused for now.
	GetGroups() []string

	// GetExtra can contain any additional information that the authenticator
	// thought was interesting.  One example would be scopes on a token.
	// Keys in this map should be namespaced to the authenticator or
	// authenticator/authorizer pair making use of them.
	// For instance: "example.org/foo" instead of "foo"
	// This is a map[string][]string because it needs to be serializeable into
	// a SubjectAccessReviewSpec.authorization.k8s.io for proper authorization
	// delegation flows
	// In order to faithfully round-trip through an impersonation flow, these keys
	// MUST be lowercase.
	GetExtra() map[string][]string

	// GetSubject return the subject for authenticated identity.
	// This will be in the form: <IdentityType>:<Identifier> and will use deprecated
	// integer id as the identitifier.
	GetSubject() string

	// GetAudience returns the audience.
	GetAudience() []string

	// GetPermissions returns Grafana permissions that authenticated access token can perform.
	GetPermissions() []string

	// GetDelegatedPermissions returns Grafana permissions that can be performed on-behalf of another identity
	GetDelegatedPermissions() []string

	// GetEmail returns the email.
	// This is only set for users.
	GetEmail() string

	// GetEmailVerified returns if the email has been verified.
	// This is only set for users
	GetEmailVerified() bool

	// GetUsername returns the username.
	// This is only set for users.
	GetUsername() string

	// GetAuthenticatedBy is the original method used to authenticate the identity.
	// Examples: password, oauth_azuread, etc
	GetAuthenticatedBy() string
}
