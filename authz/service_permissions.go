package authz

import (
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
		Permissions: authInfo.GetTokenPermissions(),
	}
	if !res.ServiceCall {
		res.Permissions = authInfo.GetTokenDelegatedPermissions()
	}
	res.Allowed = hasPermissionInToken(res.Permissions, group, resource, verb)
	return res
}
