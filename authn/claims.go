package authn

import (
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/grafana/authlib/claims"
)

var (
	_ claims.IdentityClaims = &Identity{}
	_ claims.AccessClaims   = &Access{}
	_ claims.AuthInfo       = &AuthInfo{}
	_ claims.TokenClaims    = &jwtClaims{}
)

type Claims[T any] struct {
	*jwt.Claims
	Rest T

	// The original raw token
	token string
}

type AuthInfo struct {
	IdentityClaims *Identity
	AccessClaims   *Access
}

// GetExtra implements claims.AuthInfo.
func (c *AuthInfo) GetExtra() map[string][]string {
	if c.IdentityClaims != nil && c.IdentityClaims.claims.token != "" {
		// Currently required for external k8s aggregation
		// but this should be removed in the not-to-distant future
		return map[string][]string{"id-token": {c.IdentityClaims.claims.token}}
	}
	return map[string][]string{}
}

// GetGroups implements claims.AuthInfo.
func (c *AuthInfo) GetGroups() []string {
	return []string{}
}

// GetName implements claims.AuthInfo.
func (c *AuthInfo) GetName() string {
	return c.IdentityClaims.claims.Rest.getK8sName()
}

// GetUID implements claims.AuthInfo.
func (c *AuthInfo) GetUID() string {
	return c.IdentityClaims.claims.Rest.asTypedUID()
}

type Identity struct {
	claims Claims[IDTokenClaims]
}

type Access struct {
	claims Claims[AccessTokenClaims]
}

func NewAccessClaims(c Claims[AccessTokenClaims]) claims.AccessClaims {
	return &Access{claims: c}
}

func NewIdentityClaims(c Claims[IDTokenClaims]) claims.IdentityClaims {
	return &Identity{claims: c}
}

type jwtClaims struct {
	claims *jwt.Claims
}

// Access implements claims.AuthInfo.
func (c *AuthInfo) GetAccess() claims.AccessClaims {
	return c.AccessClaims
}

// Identity implements claims.AuthInfo.
func (c *AuthInfo) GetIdentity() claims.IdentityClaims {
	return c.IdentityClaims
}

// Audience implements claims.IdentityClaims.
func (c *Identity) GetAudience() []string {
	return c.claims.Audience
}

// AuthenticatedBy implements claims.IdentityClaims.
func (c *Identity) GetAuthenticatedBy() string {
	return c.claims.Rest.AuthenticatedBy
}

// DisplayName implements claims.IdentityClaims.
func (c *Identity) GetDisplayName() string {
	return c.claims.Rest.DisplayName
}

// Email implements claims.IdentityClaims.
func (c *Identity) GetEmail() string {
	return c.claims.Rest.Email
}

// EmailVerified implements claims.IdentityClaims.
func (c *Identity) GetEmailVerified() bool {
	return c.claims.Rest.EmailVerified
}

// Expiry implements claims.IdentityClaims.
func (c *Identity) GetExpiry() *time.Time {
	if c.claims.Expiry == nil {
		return nil
	}
	t := c.claims.Expiry.Time()
	return &t
}

// ID implements claims.IdentityClaims.
func (c *Identity) GetJTI() string {
	return c.claims.ID
}

// IssuedAt implements claims.IdentityClaims.
func (c *Identity) GetIssuedAt() *time.Time {
	if c.claims.IssuedAt == nil {
		return nil
	}
	t := c.claims.IssuedAt.Time()
	return &t
}

// Issuer implements claims.IdentityClaims.
func (c *Identity) GetIssuer() string {
	return c.claims.Issuer
}

// Namespace implements claims.IdentityClaims.
func (c *Identity) GetNamespace() string {
	return c.claims.Rest.Namespace
}

// NotBefore implements claims.IdentityClaims.
func (c *Identity) GetNotBefore() *time.Time {
	if c.claims.NotBefore == nil {
		return nil
	}
	t := c.claims.NotBefore.Time()
	return &t
}

// Subject implements claims.IdentityClaims.
func (c *Identity) GetSubject() string {
	return c.claims.Subject
}

// UID implements claims.IdentityClaims.
func (c *Identity) GetRawUID() string {
	return c.claims.Rest.UID
}

// UID implements claims.IdentityClaims.
func (c *Identity) GetInternalID() int64 {
	return c.claims.Rest.InternalID
}

// UID implements claims.IdentityClaims.
func (c *Identity) GetOrgID() int64 {
	return c.claims.Rest.OrgID
}

// UID implements claims.IdentityClaims.
func (c *Identity) GetIdentityType() claims.IdentityType {
	return c.claims.Rest.Type
}

// Username implements claims.IdentityClaims.
func (c *Identity) GetUsername() string {
	return c.claims.Rest.Username
}

// Audience implements claims.IdentityClaims.
func (c *Access) GetAudience() []string {
	return c.claims.Audience
}

// Expiry implements claims.IdentityClaims.
func (c *Access) GetExpiry() *time.Time {
	if c.claims.Expiry == nil {
		return nil
	}
	t := c.claims.Expiry.Time()
	return &t
}

// ID implements claims.IdentityClaims.
func (c *Access) GetJTI() string {
	return c.claims.ID
}

// IssuedAt implements claims.IdentityClaims.
func (c *Access) GetIssuedAt() *time.Time {
	if c.claims.IssuedAt == nil {
		return nil
	}
	t := c.claims.IssuedAt.Time()
	return &t
}

// Issuer implements claims.IdentityClaims.
func (c *Access) GetIssuer() string {
	return c.claims.Issuer
}

// Namespace implements claims.IdentityClaims.
func (c *Access) GetNamespace() string {
	return c.claims.Rest.Namespace
}

// NotBefore implements claims.IdentityClaims.
func (c *Access) GetNotBefore() *time.Time {
	if c.claims.NotBefore == nil {
		return nil
	}
	t := c.claims.NotBefore.Time()
	return &t
}

// Subject implements claims.IdentityClaims.
func (c *Access) GetSubject() string {
	return c.claims.Subject
}

// DelegatedPermissions implements claims.AccessClaims.
func (c *Access) GetDelegatedPermissions() []string {
	return c.claims.Rest.DelegatedPermissions
}

// Permissions implements claims.AccessClaims.
func (c *Access) GetPermissions() []string {
	return c.claims.Rest.Permissions
}

// Scopes implements claims.AccessClaims.
func (c *Access) GetScopes() []string {
	return c.claims.Rest.Scopes
}

// Audience implements claims.IdentityClaims.
func (c *jwtClaims) GetAudience() []string {
	return c.claims.Audience
}

// Expiry implements claims.IdentityClaims.
func (c *jwtClaims) GetExpiry() *time.Time {
	if c.claims.Expiry == nil {
		return nil
	}
	t := c.claims.Expiry.Time()
	return &t
}

// ID implements claims.IdentityClaims.
func (c *jwtClaims) GetJTI() string {
	return c.claims.ID
}

// IssuedAt implements claims.IdentityClaims.
func (c *jwtClaims) GetIssuedAt() *time.Time {
	if c.claims.IssuedAt == nil {
		return nil
	}
	t := c.claims.IssuedAt.Time()
	return &t
}

// Issuer implements claims.IdentityClaims.
func (c *jwtClaims) GetIssuer() string {
	return c.claims.Issuer
}

// NotBefore implements claims.IdentityClaims.
func (c *jwtClaims) GetNotBefore() *time.Time {
	if c.claims.NotBefore == nil {
		return nil
	}
	t := c.claims.NotBefore.Time()
	return &t
}

// Subject implements claims.IdentityClaims.
func (c *jwtClaims) GetSubject() string {
	return c.claims.Subject
}
