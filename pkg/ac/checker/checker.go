package checker

// NOTE: this package is temporary, the aim is actually to make this a module

import (
	"context"
	"strings"

	"github.com/grafana/authlib/pkg/ac/models"
)

var (
	NoAccessChecker models.Checker = func(scopes ...string) bool { return false }
)

// GenerateChecker generates a function to check whether the user has access to any scope of a given list of scopes.
func GenerateChecker(ctx context.Context, permissions models.Permissions, action string, prefixes ...string) models.Checker {
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
	if len(prefixes) == 0 {
		return func(scopes ...string) bool { return (len(scopes) == 0 && len(pScopes) == 0) }
	}

	wildcards := WildcardsFromPrefixes(prefixes...)
	lookup := make(map[string]bool, len(pScopes))
	for _, s := range pScopes {
		// one scope is a wildcard => access to all resources of this type
		if wildcards.Contains(s) {
			return func(scopes ...string) bool { return true }
		}
		lookup[s] = true
	}

	return func(scopes ...string) bool {
		// search for any direct match
		for _, s := range scopes {
			if lookup[s] {
				return true
			}
		}
		return false
	}
}

// WildcardsFromPrefixes generates valid wildcards from prefixes
// users:uid: => "*", "users:*", "users:uid:*"
func WildcardsFromPrefixes(prefixes ...string) Wildcards {
	if len(prefixes) == 0 {
		return Wildcards{}
	}

	wildcards := Wildcards{"*"}
	alreadyAdded := map[string]bool{}
	for _, prefix := range prefixes {
		var b strings.Builder
		parts := strings.Split(prefix, ":")
		for _, p := range parts {
			if p == "" {
				continue
			}
			b.WriteString(p)
			b.WriteRune(':')
			wildcard := b.String() + "*"
			if !alreadyAdded[wildcard] {
				wildcards = append(wildcards, b.String()+"*")
			}
		}
	}
	return wildcards
}

// Wildcards is an helper to see if a scope is contained within it.
// ex: "users:uid:*" is included in the list of following wildcards ["*", "users:*", "users:uid:*"]
type Wildcards []string

// Contains check if wildcards contains scope
func (wildcards Wildcards) Contains(scope string) bool {
	for _, w := range wildcards {
		if scope == w {
			return true
		}
	}
	return false
}
