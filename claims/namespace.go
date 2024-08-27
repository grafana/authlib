package claims

import (
	"fmt"
	"strconv"
	"strings"
)

// NamespaceFormatter defines a function that formats a stack or organization ID
// into the expected namespace format based on the deployment environment (Cloud/On-prem).
// Example: stack-6481, org-12
type NamespaceFormatter func(int64) string

func CloudNamespaceFormatter(id int64) string {
	// TODO: change this to stacks-X when all the other dependent pieces (gcom etc.) can validate both stack-x and stacks-X
	return fmt.Sprintf("stack-%d", id)
}

// OrgNamespaceFormatter is the namespace format used in on-prem deployments
func OrgNamespaceFormatter(id int64) string {
	if id == 1 {
		return "default"
	}
	return fmt.Sprintf("org-%d", id)
}

// disambiguateNamespace is a helper to temporarily navigate the issue with cloud namespace claims being ambiguous (stack vs stacks).
func disambiguateNamespace(namespace string) string {
	return strings.Replace(namespace, "stack-", "stacks-", 1)
}

func NamespaceMatches(c Namespaced, namespace string) bool {
	actual := disambiguateNamespace(c.Namespace())
	expected := disambiguateNamespace(namespace)
	// actual should never be a "*" where ID token claims are concerned
	if actual == "*" {
		return true
	}
	return actual == expected
}

type NamespaceInfo struct {
	// The original namespace string regardless the input
	Value string

	// OrgID defined in namespace (1 when using stack ids)
	OrgID int64

	// The cloud stack ID (must match the value in cfg.Settings)
	StackID int64
}

func ParseNamespace(ns string) (NamespaceInfo, error) {
	info := NamespaceInfo{Value: ns, OrgID: -1}
	if ns == "default" {
		info.OrgID = 1
		return info, nil
	}

	if id, ok := strings.CutPrefix(ns, "org-"); ok {
		orgID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return info, fmt.Errorf("invalid org id")
		}

		if orgID < 1 {
			return info, fmt.Errorf("invalid org id")
		}
		if orgID == 1 {
			return info, fmt.Errorf("use default rather than org-1")
		}
		info.OrgID = orgID
		return info, err
	}

	if id, ok := strings.CutPrefix(ns, "stacks-"); ok {
		stackID, err := strconv.ParseInt(id, 10, 64)
		if err != nil || stackID < 1 {
			return info, fmt.Errorf("invalid stack id")
		}
		info.StackID = stackID
		info.OrgID = 1
		return info, err
	}

	// handle deprecated stack-X value
	if id, ok := strings.CutPrefix(ns, "stack-"); ok {
		stackID, err := strconv.ParseInt(id, 10, 64)
		if err != nil || stackID < 1 {
			return info, fmt.Errorf("invalid stack id")
		}
		info.StackID = stackID
		info.OrgID = 1
		return info, err
	}

	// NOTE: we can't return errors. This breaks things like cluster-scoped resources and discovery
	return info, nil
}
