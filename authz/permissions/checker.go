package permissions

// NOTE: this package is temporary, the aim is actually to make this a module

import (
	"strings"

	"github.com/grafana/authlib/authz"
)

var (
	NoAccessChecker   Checker = func(resources ...authz.Resource) bool { return false }
	FullAccessChecker Checker = func(resources ...authz.Resource) bool { return true }
)

// CompileChecker generates a function to check whether the user has access to any scope of a given list of scopes.
func CompileChecker(permissions authz.Permissions, action string, kinds ...string) Checker {
	// no permissions => no access to any resource of this type
	if len(permissions) == 0 {
		return NoAccessChecker
	}

	// no permissions for this action => no access to any resource of this type
	pScopes, ok := permissions[action]
	if !ok {
		return NoAccessChecker
	}

	// no prefix expected => only check for the action
	if len(kinds) == 0 {
		return FullAccessChecker
	}

	isWildcard := WildcardDetector(kinds...)
	lookup := make(map[string]bool, len(pScopes))
	for _, s := range pScopes {
		// one scope is a wildcard => access to all resources of this type
		if isWildcard(s) {
			return FullAccessChecker
		}
		lookup[s] = true
	}

	return func(resources ...authz.Resource) bool {
		// search for any direct match
		for i := range resources {
			if lookup[resources[i].Scope()] {
				return true
			}
		}
		return false
	}
}

// WildcardDetector is an helper to quickly assess if a scope is a wildcard of a given set of kinds.
// ex: WildcardDetector("datasources", "folders")("datasources:uid:*") => true
func WildcardDetector(kinds ...string) func(scope string) bool {
	// no kinds => no wildcard
	if len(kinds) == 0 {
		return func(scope string) bool { return false }
	}
	return func(scope string) bool {
		if scope == "*" {
			return true
		}
		for i := range kinds {
			if scope[len(scope)-1] == '*' && strings.HasPrefix(scope, kinds[i]+":") {
				return true
			}
		}
		return false
	}
}
