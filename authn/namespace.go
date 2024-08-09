package authn

import "fmt"

// NamespaceFormatter defines a function that formats a stack or organization ID
// into the expected namespace format based on the deployment environment (Cloud/On-prem).
// Example: stack-6481, org-12
type NamespaceFormatter func(int64) string

// Deprecated: use claims.CloudNamespaceFormatter
func CloudNamespaceFormatter(id int64) string {
	return fmt.Sprintf("stack-%d", id)
}

// Deprecated: use claims.CloudNamespaceFormatter
func OnPremNamespaceFormatter(id int64) string {
	if id == 1 {
		return "default"
	}
	return fmt.Sprintf("org-%d", id)
}
