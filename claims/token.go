package claims

import "time"

// AuthInfo provides access to the requested authnz info
// This includes the identity and access claims.  This interface is also designed to
// fulfil the kubernetes user requirements:
// https://github.com/kubernetes/apiserver/blob/master/pkg/authentication/user/user.go#L20
type AuthInfo interface {
	// GetName returns the name that can be shown to identify the user
	// This may be a configured display name, an email, or (worst case) a ID
	GetName() string

	// GetUID returns a unique value for a particular user that will change
	// if the user is removed from the system and another user is added with
	// the same name.
	// This will either be a full GUID, or in the form: <IdentityType>:<Identity.UID>
	GetUID() string

	// GetGroups returns the names of the groups the user is a member of
	// In grafana, this will only be populated with standard k8s names
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

	// Get the identity claims
	GetIdentity() IdentityClaims

	// Get the access claims
	GetAccess() AccessClaims
}

// TokenClaims hold the standard JWT claims
// [RFC 7519]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
type TokenClaims interface {
	// The "iss" (issuer) claim identifies the principal that issued the
	// JWT.  The processing of this claim is generally application specific.
	// The "iss" value is a case-sensitive string containing a StringOrURI
	// value.  Use of this claim is OPTIONAL.
	// [RFC 7519 §4.1.1]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer() string

	// The "sub" (subject) claim identifies the principal that is the
	// subject of the JWT.  The claims in a JWT are normally statements
	// about the subject.  The subject value MUST either be scoped to be
	// locally unique in the context of the issuer or be globally unique.
	// The processing of this claim is generally application specific.  The
	// "sub" value is a case-sensitive string containing a StringOrURI
	// value.  Use of this claim is OPTIONAL.
	// [RFC 7519 §4.1.2]: https://datatracker.ietf.org/rfc/rfc7519#section-4.1.2
	Subject() string

	// The "aud" (audience) claim identifies the recipients that the JWT is
	// intended for.  Each principal intended to process the JWT MUST
	// identify itself with a value in the audience claim.  If the principal
	// processing the claim does not identify itself with a value in the
	// "aud" claim when this claim is present, then the JWT MUST be
	// rejected.  In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value.  The
	// interpretation of audience values is generally application specific.
	// Use of this claim is OPTIONAL.
	// [RFC 7519 §4.1.3]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience() []string

	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT MUST NOT be accepted for processing.  The
	// processing of the "exp" claim requires that the current date/time
	// MUST be before the expiration date/time listed in the "exp" claim.
	// Implementers MAY provide for some small leeway, usually no more than
	// a few minutes, to account for clock skew.  Its value MUST be a number
	// containing a NumericDate value.  Use of this claim is OPTIONAL.
	// [RFC 7519 §4.1.4]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	Expiry() *time.Time

	// The "nbf" (not before) claim identifies the time before which the JWT
	// MUST NOT be accepted for processing.  The processing of the "nbf"
	// claim requires that the current date/time MUST be after or equal to
	// the not-before date/time listed in the "nbf" claim.  Implementers MAY
	// provide for some small leeway, usually no more than a few minutes, to
	// account for clock skew.  Its value MUST be a number containing a
	// NumericDate value.  Use of this claim is OPTIONAL.
	// [RFC 7519 §4.1.5]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore() *time.Time

	// The "iat" (issued at) claim identifies the time at which the JWT was
	// issued.  This claim can be used to determine the age of the JWT.  Its
	// value MUST be a number containing a NumericDate value.  Use of this
	// claim is OPTIONAL.
	// [RFC 7519 §4.1.6]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt() *time.Time

	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	// The identifier value MUST be assigned in a manner that ensures that
	// there is a negligible probability that the same value will be
	// accidentally assigned to a different data object; if the application
	// uses multiple issuers, collisions MUST be prevented among values
	// produced by different issuers as well.  The "jti" claim can be used
	// to prevent the JWT from being replayed.  The "jti" value is a case-
	// sensitive string.  Use of this claim is OPTIONAL.
	// [RFC 7519 §4.1.7]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	JTI() string
}

type IdentityClaims interface {
	TokenClaims

	// Type indicates what kind of identity this is
	IdentityType() IdentityType

	// UID is a unique identifier for this identity.
	UID() string

	// Namespace takes the form of '<type>-<id>', '*' means all namespaces.
	// In grafana the can be either org or stack.
	// The claims are valid within this namespace
	Namespace() string

	// AuthenticatedBy is the method used to authenticate the identity.
	// Examples: oauth, oauth_azuread, etc
	AuthenticatedBy() string

	// The identity email
	Email() string

	// EmailVerified indicates that the email has been verified
	EmailVerified() bool

	// Username of the user (login attribute on the Identity)
	Username() string

	// Display Name of the user (name attribute if it is set, otherwise the login or email)
	DisplayName() string
}

// Access claims indicate what the request can access independent from the identity
type AccessClaims interface {
	TokenClaims

	// Namespace takes the form of '<type>-<id>', '*' means all namespaces.
	// In grafana the can be either org or stack.
	// The claims are valid within this namespace
	Namespace() string
	// Access policy scopes
	Scopes() []string
	// Grafana roles
	Permissions() []string
	// On-behalf-of user
	DelegatedPermissions() []string
}
