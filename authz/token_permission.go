package authz

import (
	"strings"
	"unicode"
)

// TokenPermission is a group-wide grant or an exact resource/subresource grant.
// Resource and Subresource are empty for a group-wide grant.
type TokenPermission struct {
	Group       string
	Resource    string
	Subresource string
	Verb        string
}

// ParseTokenPermission parses group[/resource[/subresource]]:verb.
// It returns the parsed grant and true on success, with omitted resource and
// subresource fields left empty. Invalid or unsupported grants return a zero-value
// TokenPermission and false.
//
// Group wildcards must be allowlisted by IsAllowedWildcardGroup. Resource and
// subresource wildcards are unsupported. The first colon separates the scope
// from an opaque, non-empty verb; only the complete verb "*" acts as a wildcard
// during evaluation.
func ParseTokenPermission(permission string) (TokenPermission, bool) {
	for _, character := range permission {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return TokenPermission{}, false
		}
	}

	scope, verb, hasVerb := strings.Cut(permission, ":")
	if !hasVerb || verb == "" {
		return TokenPermission{}, false
	}

	scopeParts := strings.Split(scope, "/")
	if len(scopeParts) > 3 {
		return TokenPermission{}, false
	}

	group := scopeParts[0]
	if group == "" {
		return TokenPermission{}, false
	}
	if strings.Contains(group, "*") && !IsAllowedWildcardGroup(group) {
		return TokenPermission{}, false
	}

	// An omitted resource grants group-wide access, so empty path segments must
	// not be treated as omitted resources.
	for _, resourceName := range scopeParts[1:] {
		if resourceName == "" || strings.Contains(resourceName, "*") {
			return TokenPermission{}, false
		}
	}

	grant := TokenPermission{Group: group, Verb: verb}
	if len(scopeParts) >= 2 {
		grant.Resource = scopeParts[1]
	}
	if len(scopeParts) == 3 {
		grant.Subresource = scopeParts[2]
	}
	return grant, true
}
