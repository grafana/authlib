package authz

// NOTE: this package is temporary, the aim is actually to make this a module

import (
	"strings"
)

var (
	noAccessChecker   checker = func(resources ...Resource) bool { return false }
	fullAccessChecker checker = func(resources ...Resource) bool { return true }
)

// compileChecker generates a function to check whether the user has access to any scope of a given list of scopes.
func compileChecker(permissions Permissions, action string, kinds ...string) checker {
	// no permissions => no access to any resource of this type
	if len(permissions) == 0 {
		return noAccessChecker
	}

	// no permissions for this action => no access to any resource of this type
	pScopes, ok := permissions[action]
	if !ok {
		return noAccessChecker
	}

	// no prefix expected => only check for the action
	if len(kinds) == 0 {
		return fullAccessChecker
	}

	isWildcard := WildcardDetector(kinds...)
	lookup := make(map[string]bool, len(pScopes))
	for _, s := range pScopes {
		// one scope is a wildcard => access to all resources of this type
		if isWildcard(s) {
			return fullAccessChecker
		}
		lookup[s] = true
	}

	return func(resources ...Resource) bool {
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
		split := strings.Split(scope, ":")
		if len(split) != 3 {
			// the last part of the scope is definitely not a wildcard
			return false
		}
		for i := range kinds {
			if split[0] == kinds[i] && split[2] == "*" {
				return true
			}
		}
		return false
	}
}
