package authz

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/grafana/authlib/authn"
)

var (
	ErrorMissingIDToken               = status.Errorf(codes.Unauthenticated, "unauthenticated: missing id token")
	ErrorIDTokenNamespaceMismatch     = status.Errorf(codes.PermissionDenied, "unauthorized: id token namespace does not match expected namespace")
	ErrorAccessTokenNamespaceMismatch = status.Errorf(codes.PermissionDenied, "unauthorized: access token namespace does not match expected namespace")
)

type NamespaceAuthorizer interface {
	Validate(caller authn.CallerAuthInfo, stackID int64) error
}

type NamespaceAuthorizerOption func(*NamespaceAuthorizerImpl)

type NamespaceAuthorizerImpl struct {
	// namespaceFmt is the namespace formatter used to generate the expected namespace.
	// Ex: "stack-%d" -> "stack-12"
	namespaceFmt authn.NamespaceFormatter

	// idTokenEnabled is a flag to enable ID token namespace validation.
	idTokenEnabled bool
	// idTokenRequired is a flag to require the ID token for namespace validation.
	// if the ID is not provided and required is true, an error is returned.
	idTokenRequired bool
	// accessTokenEnabled is a flag to enable access token namespace validation.
	accessTokenEnabled bool
}

// WithIDTokenNamespaceAuthorizerOption enables ID token namespace validation.
// If required is true, the ID token is required for validation.
func WithIDTokenNamespaceAuthorizerOption(required bool) NamespaceAuthorizerOption {
	return func(na *NamespaceAuthorizerImpl) {
		na.idTokenEnabled = true
		na.idTokenRequired = required
	}
}

// WithDisableAccessTokenNamespaceAuthorizerOption disables access token namespace validation.
func WithDisableAccessTokenNamespaceAuthorizerOption() NamespaceAuthorizerOption {
	return func(na *NamespaceAuthorizerImpl) {
		na.accessTokenEnabled = false
	}
}

// NewNamespaceAuthorizer creates a new namespace authorizer.
// If both ID token and access token are disabled, the authorizer will always return nil.
func NewNamespaceAuthorizer(namespaceFmt authn.NamespaceFormatter, opts ...NamespaceAuthorizerOption) *NamespaceAuthorizerImpl {
	na := &NamespaceAuthorizerImpl{
		namespaceFmt:       namespaceFmt,
		idTokenEnabled:     false,
		idTokenRequired:    false,
		accessTokenEnabled: true,
	}

	for _, opt := range opts {
		opt(na)
	}

	return na
}

func (na *NamespaceAuthorizerImpl) Validate(caller authn.CallerAuthInfo, stackID int64) error {
	expectedNamespace := na.namespaceFmt(stackID)
	if na.idTokenEnabled {
		if caller.IDTokenClaims == nil {
			if na.idTokenRequired {
				return ErrorMissingIDToken
			}
		} else if caller.IDTokenClaims.Rest.Namespace != expectedNamespace {
			return ErrorIDTokenNamespaceMismatch
		}
	}
	if na.accessTokenEnabled && !caller.AccessTokenClaims.Rest.NamespaceMatches(expectedNamespace) {
		return ErrorAccessTokenNamespaceMismatch
	}
	return nil
}
