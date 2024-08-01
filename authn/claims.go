package authn

import (
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/grafana/authlib/claims"
)

var (
	_ claims.IdentityClaims = &Identity{}
	_ claims.AccessClaims   = &Access{}
	_ claims.AuthInfo       = &CallerAuthInfoNEXT{}
)

type Claims[T any] struct {
	*jwt.Claims
	Rest T
}

type CallerAuthInfoNEXT struct {
	IdentityClaims *Identity
	AccessClaims   *Access
}

type Identity struct {
	claims Claims[IDTokenClaims]
}

type Access struct {
	claims Claims[AccessTokenClaims]
}

// Access implements claims.AuthInfo.
func (c *CallerAuthInfoNEXT) Access() claims.AccessClaims {
	return c.AccessClaims
}

// Identity implements claims.AuthInfo.
func (c *CallerAuthInfoNEXT) Identity() claims.IdentityClaims {
	return c.IdentityClaims
}

// Audience implements claims.IdentityClaims.
func (c *Identity) Audience() []string {
	return c.claims.Audience
}

// AuthenticatedBy implements claims.IdentityClaims.
func (c *Identity) AuthenticatedBy() string {
	return c.claims.Rest.AuthenticatedBy
}

// DisplayName implements claims.IdentityClaims.
func (c *Identity) DisplayName() string {
	return c.claims.Rest.DisplayName
}

// Email implements claims.IdentityClaims.
func (c *Identity) Email() string {
	return c.claims.Rest.Email
}

// EmailVerified implements claims.IdentityClaims.
func (c *Identity) EmailVerified() bool {
	return c.claims.Rest.EmailVerified
}

// Expiry implements claims.IdentityClaims.
func (c *Identity) Expiry() *time.Time {
	if c.claims.Expiry == nil {
		return nil
	}
	t := c.claims.Expiry.Time()
	return &t
}

// ID implements claims.IdentityClaims.
func (c *Identity) ID() string {
	return c.claims.ID
}

// IssuedAt implements claims.IdentityClaims.
func (c *Identity) IssuedAt() *time.Time {
	if c.claims.IssuedAt == nil {
		return nil
	}
	t := c.claims.IssuedAt.Time()
	return &t
}

// Issuer implements claims.IdentityClaims.
func (c *Identity) Issuer() string {
	return c.claims.Issuer
}

// Namespace implements claims.IdentityClaims.
func (c *Identity) Namespace() string {
	return c.claims.Rest.Namespace
}

// NotBefore implements claims.IdentityClaims.
func (c *Identity) NotBefore() *time.Time {
	if c.claims.NotBefore == nil {
		return nil
	}
	t := c.claims.NotBefore.Time()
	return &t
}

// Subject implements claims.IdentityClaims.
func (c *Identity) Subject() string {
	return c.claims.Subject
}

// UID implements claims.IdentityClaims.
func (c *Identity) UID() string {
	return c.claims.Rest.UID
}

// Username implements claims.IdentityClaims.
func (c *Identity) Username() string {
	return c.claims.Rest.Username
}

// Audience implements claims.IdentityClaims.
func (c *Access) Audience() []string {
	return c.claims.Audience
}

// Expiry implements claims.IdentityClaims.
func (c *Access) Expiry() *time.Time {
	if c.claims.Expiry == nil {
		return nil
	}
	t := c.claims.Expiry.Time()
	return &t
}

// ID implements claims.IdentityClaims.
func (c *Access) ID() string {
	return c.claims.ID
}

// IssuedAt implements claims.IdentityClaims.
func (c *Access) IssuedAt() *time.Time {
	if c.claims.IssuedAt == nil {
		return nil
	}
	t := c.claims.IssuedAt.Time()
	return &t
}

// Issuer implements claims.IdentityClaims.
func (c *Access) Issuer() string {
	return c.claims.Issuer
}

// Namespace implements claims.IdentityClaims.
func (c *Access) Namespace() string {
	return c.claims.Rest.Namespace
}

// NotBefore implements claims.IdentityClaims.
func (c *Access) NotBefore() *time.Time {
	if c.claims.NotBefore == nil {
		return nil
	}
	t := c.claims.NotBefore.Time()
	return &t
}

// Subject implements claims.IdentityClaims.
func (c *Access) Subject() string {
	return c.claims.Subject
}

// DelegatedPermissions implements claims.AccessClaims.
func (c *Access) DelegatedPermissions() []string {
	return c.claims.Rest.DelegatedPermissions
}

// Permissions implements claims.AccessClaims.
func (c *Access) Permissions() []string {
	return c.claims.Rest.Permissions
}

// Scopes implements claims.AccessClaims.
func (c *Access) Scopes() []string {
	return c.claims.Rest.Scopes
}
