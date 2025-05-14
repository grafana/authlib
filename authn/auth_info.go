package authn

import (
	"strings"

	"github.com/grafana/authlib/types"
)

var _ types.AuthInfo = (*AuthInfo)(nil)

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

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		if actor.Type == types.TypeUser {
			return actor.getK8sName()
		}

		return actor.Subject
	}

	return a.at.Subject
}

func (a *AuthInfo) GetUID() string {
	if a.id != nil {
		return a.id.Rest.getTypedUID()
	}

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		if actor.Type == types.TypeUser {
			return actor.getTypedUID()
		}

		return actor.Subject
	}

	return a.at.Subject
}

func (a *AuthInfo) GetIdentifier() string {
	if a.id != nil {
		return a.id.Rest.Identifier
	}

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		if actor.Type == types.TypeUser {
			return actor.Identifier
		}

		return strings.TrimPrefix(actor.Subject, string(types.TypeAccessPolicy)+":")
	}

	return strings.TrimPrefix(a.at.Subject, string(types.TypeAccessPolicy)+":")
}

func (a *AuthInfo) GetIdentityType() types.IdentityType {
	if a.id != nil {
		return a.id.Rest.Type
	}

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		if actor.Type == types.TypeUser {
			return types.TypeUser
		}
	}

	return types.TypeAccessPolicy
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

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		return actor.Subject
	}

	return a.at.Subject
}

func (a *AuthInfo) GetAuthenticatedBy() string {
	if a.id != nil {
		return a.id.Rest.AuthenticatedBy
	}

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		if actor.Type == types.TypeUser {
			return actor.AuthenticatedBy
		}
	}

	return ""
}

func (a *AuthInfo) GetTokenPermissions() []string {
	// If it's a service acting on behalf of a user
	// we should not check token permission but delegated permissions instead
	// If it's a service acting on behalf of a second service
	// we currently just check the first service permissions
	if a.id != nil && a.id.Rest.Type != types.TypeAccessPolicy {
		return []string{}
	}
	return a.at.Rest.Permissions
}

func (a *AuthInfo) GetTokenDelegatedPermissions() []string {
	return a.at.Rest.DelegatedPermissions
}

func (a *AuthInfo) GetEmail() string {
	if a.id != nil {
		return a.id.Rest.Email
	}

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		if actor.Type == types.TypeUser {
			return actor.Email
		}
	}

	return ""
}

func (a *AuthInfo) GetEmailVerified() bool {
	if a.id != nil {
		return a.id.Rest.EmailVerified
	}

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		if actor.Type == types.TypeUser {
			return actor.EmailVerified
		}
	}

	return false
}

func (a *AuthInfo) GetUsername() string {
	if a.id != nil {
		return a.id.Rest.Username
	}

	actor := a.at.Rest.getInnermostActor()
	if actor != nil {
		if actor.Type == types.TypeUser {
			return actor.Username
		}
	}

	return ""
}

func (a *AuthInfo) GetIDToken() string {
	if a.id != nil {
		return a.id.token
	}

	return a.at.token
}
