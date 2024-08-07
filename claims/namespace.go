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
	return fmt.Sprintf("stack-%d", id)
}

// OrgNamespaceFormatter is the namespace format used in on-prem deployments
func OrgNamespaceFormatter(id int64) string {
	if id == 1 {
		return "default"
	}
	return fmt.Sprintf("org-%d", id)
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

	if strings.HasPrefix(ns, "org-") {
		id, err := strconv.ParseInt(ns[4:], 10, 64)
		if id < 1 {
			return info, fmt.Errorf("invalid org id")
		}
		if id == 1 {
			return info, fmt.Errorf("use default rather than org-1")
		}
		info.OrgID = id
		return info, err
	}

	if strings.HasPrefix(ns, "stack-") {
		stackIDStr := ns[6:]
		stackID, err := strconv.ParseInt(stackIDStr, 10, 64)
		if err != nil || stackID < 1 {
			return info, fmt.Errorf("invalid stack id")
		}
		info.StackID = stackID
		info.OrgID = 1
		return info, nil
	}
	return info, nil
}
