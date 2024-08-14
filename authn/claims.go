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

// Extra implements claims.AuthInfo.
func (c *AuthInfo) GetExtra() map[string][]string {
	if c.IdentityClaims != nil && c.IdentityClaims.claims.token != "" {
		// Currently required for external k8s aggregation
		// but this should be removed in the not-to-distant future
		return map[string][]string{"id-token": {c.IdentityClaims.claims.token}}
	}
	return map[string][]string{}
}

// Groups implements claims.AuthInfo.
func (c *AuthInfo) GetGroups() []string {
	return []string{}
}

// Name implements claims.AuthInfo.
func (c *AuthInfo) GetName() string {
	return c.IdentityClaims.claims.Rest.getK8sName()
}

// UID implements claims.AuthInfo.
func (c *AuthInfo) GetUID() string {
	return c.IdentityClaims.claims.Rest.asTypedUID()
}

type Identity struct {
	claims Claims[IDTokenClaims]
}

type Access struct {
	claims Claims[AccessTokenClaims]
}

func NewAccessClaims(c Claims[AccessTokenClaims]) *Access {
	return &Access{claims: c}
}

func NewIdentityClaims(c Claims[IDTokenClaims]) *Identity {
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
func (c *Identity) JTI() string {
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

// Identifier implements claims.IdentityClaims.
func (c *Identity) Identifier() string {
	return c.claims.Rest.Identifier
}

// UID implements claims.IdentityClaims.
func (c *Identity) IdentityType() claims.IdentityType {
	return c.claims.Rest.Type
}

// Username implements claims.IdentityClaims.
func (c *Identity) Username() string {
	return c.claims.Rest.Username
}

// Audience implements claims.IdentityClaims.
func (c *Access) Audience() []string {
	return c.claims.Audience
}

func (c *Identity) IsNil() bool {
	return c == nil
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
func (c *Access) JTI() string {
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

func (c *Access) IsNil() bool {
	return c == nil
}

// Audience implements claims.IdentityClaims.
func (c *jwtClaims) Audience() []string {
	return c.claims.Audience
}

// Expiry implements claims.IdentityClaims.
func (c *jwtClaims) Expiry() *time.Time {
	if c.claims.Expiry == nil {
		return nil
	}
	t := c.claims.Expiry.Time()
	return &t
}

// ID implements claims.IdentityClaims.
func (c *jwtClaims) JTI() string {
	return c.claims.ID
}

// IssuedAt implements claims.IdentityClaims.
func (c *jwtClaims) IssuedAt() *time.Time {
	if c.claims.IssuedAt == nil {
		return nil
	}
	t := c.claims.IssuedAt.Time()
	return &t
}

// Issuer implements claims.IdentityClaims.
func (c *jwtClaims) Issuer() string {
	return c.claims.Issuer
}

// NotBefore implements claims.IdentityClaims.
func (c *jwtClaims) NotBefore() *time.Time {
	if c.claims.NotBefore == nil {
		return nil
	}
	t := c.claims.NotBefore.Time()
	return &t
}

// Subject implements claims.IdentityClaims.
func (c *jwtClaims) Subject() string {
	return c.claims.Subject
}
