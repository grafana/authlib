package authz

import (
	"github.com/grafana/authlib/authn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	namespaceFmt authn.NamespaceFormatter

	idTokenEnabled     bool
	idTokenRequired    bool
	accessTokenEnabled bool
}

func WithIDTokenNamespaceAuthorizerOption(required bool) NamespaceAuthorizerOption {
	return func(na *NamespaceAuthorizerImpl) {
		na.idTokenEnabled = true
		na.idTokenRequired = required
	}
}

func WithDisableAccessTokenNamespaceAuthorizerOption() NamespaceAuthorizerOption {
	return func(na *NamespaceAuthorizerImpl) {
		na.accessTokenEnabled = false
	}
}

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
