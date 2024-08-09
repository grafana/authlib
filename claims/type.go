package claims

import (
	"errors"
)

var (
	ErrInvalidTypedID = errors.New("auth.identity.invalid-typed-id")
)

// The type of identity
// +enum
type IdentityType string

const (
	TypeUser           IdentityType = "user"
	TypeAPIKey         IdentityType = "api-key"
	TypeServiceAccount IdentityType = "service-account"
	TypeAnonymous      IdentityType = "anonymous"
	TypeRenderService  IdentityType = "render"
	TypeAccessPolicy   IdentityType = "access-policy"
	TypeProvisioning   IdentityType = "provisioning"
	TypeEmpty          IdentityType = ""
)

func (n IdentityType) String() string {
	return string(n)
}

func ParseType(str string) (IdentityType, error) {
	switch str {
	case string(TypeUser):
		return TypeUser, nil
	case string(TypeAPIKey):
		return TypeAPIKey, nil
	case string(TypeServiceAccount):
		return TypeServiceAccount, nil
	case string(TypeAnonymous):
		return TypeAnonymous, nil
	case string(TypeRenderService):
		return TypeRenderService, nil
	case string(TypeAccessPolicy):
		return TypeAccessPolicy, nil
	default:
		return "", ErrInvalidTypedID
	}
}

// IsIdentityType returns true if type matches any expected identity type
func IsIdentityType(typ IdentityType, expected ...IdentityType) bool {
	for _, e := range expected {
		if typ == e {
			return true
		}
	}
	return false
}
