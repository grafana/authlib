package authz

import (
	"slices"
	"strings"

	"github.com/grafana/authlib/types"
)

// ServiceEvaluationResult contains the result of a service permission check along with debug information
type ServiceEvaluationResult struct {
	// ServiceCall indicates if the call was made by a service (access policy) identity
	ServiceCall bool
	// Allowed indicates if the permission check passed
	Allowed bool
	// Permissions lists the permissions present in the token used for the check
	Permissions []string
}

// CheckServicePermissions focuses on checking the service-related permissions within the provided AuthInfo.
func CheckServicePermissions(authInfo types.AuthInfo, group, resource, verb string) ServiceEvaluationResult {
	res := ServiceEvaluationResult{
		ServiceCall: types.IsIdentityType(authInfo.GetIdentityType(), types.TypeAccessPolicy),
	}
	if res.ServiceCall {
		res.Permissions = authInfo.GetTokenPermissions()
	} else {
		res.Permissions = authInfo.GetTokenDelegatedPermissions()
	}
	res.Allowed = hasPermissionInToken(res.Permissions, group, resource, verb)
	return res
}

func hasPermissionInToken(tokenPermissions []string, group, resource, verb string) bool {
	verbs := []string{verb}

	// we always map list to get for authz
	// to be backward compatible with access tokens we accept both for now
	if verb == "list" {
		verbs = append(verbs, "get")
	}

	for _, p := range tokenPermissions {
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			continue
		}
		pVerb := parts[1]
		if pVerb != "*" && !slices.Contains(verbs, pVerb) {
			continue
		}

		parts = strings.SplitN(parts[0], "/", 2)
		switch len(parts) {
		case 1:
			if parts[0] == group {
				return true
			}
		case 2:
			if parts[0] == group && parts[1] == resource {
				return true
			}
		}
	}
	return false
}
