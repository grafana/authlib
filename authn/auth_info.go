package authn

import (
	"strings"

	"github.com/grafana/authlib/claims"
)

var _ claims.AuthInfo = (*AuthInfo)(nil)

type AuthInfo struct {
	at Claims[AccessTokenClaims]
	id *Claims[IDTokenClaims]
}

func NewAccessTokenAuthInfo(at Claims[AccessTokenClaims]) *AuthInfo {
	return &AuthInfo{
		at: at,
	}
}

func NewIDTokenAuthInfo(at Claims[AccessTokenClaims], id *Claims[IDTokenClaims]) *AuthInfo {
	return &AuthInfo{
		at: at,
		id: id,
	}
}

func (a *AuthInfo) GetName() string {
	if a.id != nil {
		return a.id.Rest.getK8sName()
	}
	return a.at.Subject
}

func (a *AuthInfo) GetUID() string {
	if a.id != nil {
		return a.id.Rest.getTypedUID()
	}
	return a.at.Subject
}

func (a *AuthInfo) GetIdentifier() string {
	if a.id != nil {
		return a.id.Rest.Identifier
	}
	return strings.TrimPrefix(a.at.Subject, string(claims.TypeAccessPolicy)+":")
}

func (a *AuthInfo) GetIdentityType() claims.IdentityType {
	if a.id != nil {
		return a.id.Rest.Type
	}
	return claims.TypeAccessPolicy
}

func (a *AuthInfo) GetNamespace() string {
	if a.id != nil {
		return a.id.Rest.Namespace
	}
	return a.at.Rest.Namespace
}

func (a *AuthInfo) GetGroups() []string {
	return []string{}
}

func (a *AuthInfo) GetExtra() map[string][]string {
	if a.id != nil {
		// Currently required for external k8s aggregation
		// but this should be removed in the not-to-distant future
		return map[string][]string{"id-token": {a.id.token}}
	}
	return map[string][]string{}
}

func (a *AuthInfo) GetAudience() []string {
	return a.at.Audience
}

func (a *AuthInfo) GetSubject() string {
	if a.id != nil {
		return a.id.Subject
	}
	return a.at.Subject
}

func (a *AuthInfo) GetAuthenticatedBy() string {
	if a.id != nil {
		return a.id.Rest.AuthenticatedBy
	}
	return ""
}

func (a *AuthInfo) GetPermissions() []string {
	return a.at.Rest.Permissions
}

func (a *AuthInfo) GetDelegatedPermissions() []string {
	return a.at.Rest.DelegatedPermissions
}

func (a *AuthInfo) GetEmail() string {
	if a.id != nil {
		return a.id.Rest.Email
	}
	return ""
}

func (a *AuthInfo) GetEmailVerified() bool {
	if a.id != nil {
		return a.id.Rest.EmailVerified
	}
	return false
}

func (a *AuthInfo) GetUsername() string {
	if a.id != nil {
		return a.id.Rest.Username
	}
	return a.at.Subject
}
