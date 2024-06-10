package authn

import (
	"fmt"
	"strconv"
	"strings"
)

type Namespace string

const (
	NamespaceUser           Namespace = "user"
	NamespaceAPIKey         Namespace = "api-key"
	NamespaceServiceAccount Namespace = "service-account"
	NamespaceAnonymous      Namespace = "anonymous"
	NamespaceRenderService  Namespace = "render"
	NamespaceAccessPolicy   Namespace = "access-policy"
	NamespaceEmpty          Namespace = ""
)

// IsNamespace returns true if namespace matches any expected namespace
func IsNamespace(namespace Namespace, expected ...Namespace) bool {
	for _, e := range expected {
		if namespace == e {
			return true
		}
	}

	return false
}

func (n Namespace) String() string {
	return string(n)
}

func ParseNamespace(str string) (Namespace, error) {
	switch str {
	case string(NamespaceUser):
		return NamespaceUser, nil
	case string(NamespaceAPIKey):
		return NamespaceAPIKey, nil
	case string(NamespaceServiceAccount):
		return NamespaceServiceAccount, nil
	case string(NamespaceAnonymous):
		return NamespaceAnonymous, nil
	case string(NamespaceRenderService):
		return NamespaceRenderService, nil
	case string(NamespaceAccessPolicy):
		return NamespaceAccessPolicy, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidNamespacedID, str)
	}
}

var AnonymousNamespaceID = NewNamespacedID(NamespaceAnonymous, 0)

func ParseNamespaceID(str string) (NamespacedID, error) {
	var namespaceID NamespacedID

	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return namespaceID, fmt.Errorf("%w: should have two parts", ErrInvalidNamespacedID)
	}

	namespace, err := ParseNamespace(parts[0])
	if err != nil {
		return namespaceID, err
	}

	namespaceID.id = parts[1]
	namespaceID.namespace = namespace

	return namespaceID, nil
}

// MustParseNamespaceID parses namespace id, it will panic if it fails to do so.
// Suitable to use in tests or when we can guarantee that we pass a correct format.
func MustParseNamespaceID(str string) NamespacedID {
	namespaceID, err := ParseNamespaceID(str)
	if err != nil {
		panic(err)
	}
	return namespaceID
}

func NewNamespacedID(namespace Namespace, id int64) NamespacedID {
	return NamespacedID{
		id:        strconv.FormatInt(id, 10),
		namespace: namespace,
	}
}

// NewNamespaceIDString creates a new NamespaceID with a string id
func NewNamespacedIDString(namespace Namespace, id string) NamespacedID {
	return NamespacedID{
		id:        id,
		namespace: namespace,
	}
}

// FIXME: use this instead of encoded string through the codebase
type NamespacedID struct {
	id        string
	namespace Namespace
}

func (ni NamespacedID) ID() string {
	return ni.id
}

// UserID will try to parse and int64 identifier if namespace is either user or service-account.
// For all other namespaces '0' will be returned.
func (ni NamespacedID) UserID() (int64, error) {
	if ni.IsNamespace(NamespaceUser, NamespaceServiceAccount) {
		return ni.ParseInt()
	}
	return 0, nil
}

// ParseInt will try to parse the id as an int64 identifier.
func (ni NamespacedID) ParseInt() (int64, error) {
	return strconv.ParseInt(ni.id, 10, 64)
}

func (ni NamespacedID) Namespace() Namespace {
	return ni.namespace
}

func (ni NamespacedID) IsNamespace(expected ...Namespace) bool {
	return IsNamespace(ni.namespace, expected...)
}

func (ni NamespacedID) String() string {
	return fmt.Sprintf("%s:%s", ni.namespace, ni.id)
}

func (ni NamespacedID) IsValid() bool {
	return ni.namespace != NamespaceEmpty && ni.id != ""
}
