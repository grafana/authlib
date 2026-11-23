package authn_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/authz"
	"github.com/grafana/authlib/types"
)

const (
	bindingAudience    = "resource-server"
	bindingNamespace   = "stacks-1"
	bindingPermission  = "dashboards.grafana.app/dashboards:get"
	bindingServicePerm = "dashboards.grafana.app/dashboards:delete"
	bindingGroup       = "dashboards.grafana.app"
	bindingResource    = "dashboards"
	bindingVerb        = "get"
	bindingOtherVerb   = "delete"

	headerAccessToken = "X-Access-Token"
	headerIDToken     = "X-Grafana-Id"
)

// sequencedTokenProvider returns a different token on each read.
// The first value is the caller's token. Later values exist so a subject
// check that verifies one copy and then reads the provider again cannot
// authorize a different identity.
type sequencedTokenProvider struct {
	access []string
	id     []string
	ai     int
	ii     int
}

func (p *sequencedTokenProvider) AccessToken(context.Context) (string, bool) {
	token := p.access[p.ai]
	if p.ai+1 < len(p.access) {
		p.ai++
	}
	return token, token != ""
}

func (p *sequencedTokenProvider) IDToken(context.Context) (string, bool) {
	token := p.id[p.ii]
	if p.ii+1 < len(p.id) {
		p.ii++
	}
	return token, token != ""
}

type bindingEnv struct {
	auth *authn.DefaultAuthenticator
	key  *ecdsa.PrivateKey
	kid  string
}

func newBindingEnv(t *testing.T) bindingEnv {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := "binding-test-key"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		payload, encErr := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     kid,
			Algorithm: string(jose.ES256),
		}}})
		require.NoError(t, encErr)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(server.Close)

	keys := authn.NewKeyRetriever(authn.KeyRetrieverConfig{SigningKeysURL: server.URL})
	return bindingEnv{
		auth: authn.NewDefaultAuthenticator(
			authn.NewAccessTokenVerifier(authn.VerifierConfig{AllowedAudiences: []string{bindingAudience}}, keys),
			authn.NewIDTokenVerifier(authn.VerifierConfig{}, keys),
		),
		key: key,
		kid: kid,
	}
}

func (e bindingEnv) sign(t *testing.T, typ, subject string, body any, audience []string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: e.key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"kid": e.kid,
			"typ": typ,
		},
	})
	require.NoError(t, err)

	std := jwt.Claims{
		Subject:  subject,
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Audience: audience,
	}
	token, err := jwt.Signed(signer).Claims(body).Claims(std).Serialize()
	require.NoError(t, err)
	return token
}

func userActor(subject, identifier, email string) *authn.ActorClaims {
	return &authn.ActorClaims{
		Subject: subject,
		IDTokenClaims: authn.IDTokenClaims{
			Identifier: identifier,
			Type:       types.TypeUser,
			Email:      email,
		},
	}
}

func identityActor(subject, identifier, email string, typ types.IdentityType) *authn.ActorClaims {
	return &authn.ActorClaims{
		Subject: subject,
		IDTokenClaims: authn.IDTokenClaims{
			Identifier: identifier,
			Type:       typ,
			Email:      email,
		},
	}
}

func (e bindingEnv) accessToken(t *testing.T, namespace string, actor *authn.ActorClaims) string {
	t.Helper()
	return e.sign(t, authn.TokenTypeAccess, "access-policy:svc", authn.AccessTokenClaims{
		Namespace:            namespace,
		DelegatedPermissions: []string{bindingPermission},
		Permissions:          []string{bindingServicePerm},
		ServiceIdentity:      "dashboard-service",
		Actor:                actor,
	}, []string{bindingAudience})
}

func (e bindingEnv) idToken(t *testing.T, subject string, claims authn.IDTokenClaims) string {
	t.Helper()
	return e.sign(t, authn.TokenTypeID, subject, claims, nil)
}

func userID(identifier, namespace, email string) authn.IDTokenClaims {
	return authn.IDTokenClaims{
		Identifier: identifier,
		Type:       types.TypeUser,
		Namespace:  namespace,
		Email:      email,
		Username:   email,
	}
}

func requireBoundPairRejected(t *testing.T, info types.AuthInfo, err error) {
	t.Helper()
	if err == nil {
		if info == nil {
			t.Fatal("Authenticate returned no error and no identity")
		}
		decision := authz.CheckServicePermissions(info, bindingGroup, bindingResource, bindingVerb)
		t.Fatalf("authenticated subject %q uid %q type %q namespace %q email %q delegated %v serviceCall %v allowed %v; an identity actor must stay bound to the ID token subject",
			info.GetSubject(), info.GetUID(), info.GetIdentityType(), info.GetNamespace(), info.GetEmail(),
			info.GetTokenDelegatedPermissions(), decision.ServiceCall, decision.Allowed)
	}
	require.Nil(t, info)
}

func requireAuthorizedAs(t *testing.T, info types.AuthInfo, err error, subject, uid, email string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, subject, info.GetSubject())
	require.Equal(t, uid, info.GetUID())
	require.Equal(t, email, info.GetEmail())
	require.Equal(t, []string{bindingPermission}, info.GetTokenDelegatedPermissions())
	require.Empty(t, info.GetTokenPermissions())

	allowed := authz.CheckServicePermissions(info, bindingGroup, bindingResource, bindingVerb)
	require.False(t, allowed.ServiceCall)
	require.True(t, allowed.Allowed)
	require.Equal(t, []string{bindingPermission}, allowed.Permissions)

	denied := authz.CheckServicePermissions(info, bindingGroup, bindingResource, bindingOtherVerb)
	require.False(t, denied.ServiceCall)
	require.False(t, denied.Allowed)
}

func TestIDTokenDoesNotReplaceBoundActor(t *testing.T) {
	env := newBindingEnv(t)
	ctx := context.Background()

	userA := userActor("user:1", "1", "actor-a@example.com")
	accessForA := env.accessToken(t, bindingNamespace, userA)
	wildcardForA := env.accessToken(t, "*", userA)
	idA := env.idToken(t, "user:1", userID("1", bindingNamespace, "id-a@example.com"))
	idB := env.idToken(t, "user:2", userID("2", bindingNamespace, "user-b@example.com"))
	idBOtherNS := env.idToken(t, "user:2", userID("2", "stacks-9", "user-b@example.com"))

	serviceAccountAccess := env.accessToken(t, bindingNamespace, identityActor("service-account:9", "9", "sa@example.com", types.TypeServiceAccount))
	anonymousAccess := env.accessToken(t, bindingNamespace, identityActor("anonymous:anon", "anon", "", types.TypeAnonymous))

	// Innermost identity is user A. The outer actor subject is user B, which must not satisfy the binding.
	nested := env.accessToken(t, bindingNamespace, &authn.ActorClaims{
		Subject: "user:2",
		IDTokenClaims: authn.IDTokenClaims{
			Identifier: "outer",
			Type:       types.TypeAccessPolicy,
		},
		Actor: userActor("user:1", "1", "actor-a@example.com"),
	})

	policyActor := env.accessToken(t, bindingNamespace, &authn.ActorClaims{
		Subject: "access-policy:other",
		IDTokenClaims: authn.IDTokenClaims{
			Identifier: "other",
			Type:       types.TypeAccessPolicy,
		},
	})
	noActor := env.accessToken(t, bindingNamespace, nil)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: otherKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"kid": env.kid, "typ": authn.TokenTypeID},
	})
	require.NoError(t, err)
	badSignatureID, err := jwt.Signed(otherSigner).
		Claims(userID("1", bindingNamespace, "id-a@example.com")).
		Claims(jwt.Claims{Subject: "user:1", Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}).
		Serialize()
	require.NoError(t, err)

	httpProvider := func(access, id, accessPrefix, idPrefix string) authn.TokenProvider {
		req := httptest.NewRequest(http.MethodPost, "http://service.example/query", nil)
		req.Header.Set(headerAccessToken, accessPrefix+access)
		if id != "" {
			req.Header.Set(headerIDToken, idPrefix+id)
		}
		return authn.NewHTTPTokenProvider(req)
	}
	grpcProvider := func(access, id string) authn.TokenProvider {
		pairs := []string{"X-Access-Token", access}
		if id != "" {
			pairs = append(pairs, "X-Id-Token", id)
		}
		return authn.NewGRPCTokenProvider(metadata.Pairs(pairs...))
	}

	t.Run("http bearer headers", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, httpProvider(accessForA, idB, "Bearer ", "Bearer "))
		requireBoundPairRejected(t, info, err)
	})

	t.Run("http raw headers", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, httpProvider(accessForA, idB, "", ""))
		requireBoundPairRejected(t, info, err)
	})

	t.Run("grpc metadata", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, grpcProvider(accessForA, idB))
		requireBoundPairRejected(t, info, err)
	})

	t.Run("wildcard namespace", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, grpcProvider(wildcardForA, idBOtherNS))
		requireBoundPairRejected(t, info, err)
	})

	t.Run("service account actor", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, grpcProvider(serviceAccountAccess, idB))
		requireBoundPairRejected(t, info, err)
	})

	t.Run("anonymous actor", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, grpcProvider(anonymousAccess, idB))
		requireBoundPairRejected(t, info, err)
	})

	t.Run("innermost actor is the bound identity", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, grpcProvider(nested, idB))
		requireBoundPairRejected(t, info, err)
	})

	t.Run("reread id token cannot authorize the other user", func(t *testing.T) {
		// First ID token is user B. A later read is user A and would match the actor.
		provider := &sequencedTokenProvider{access: []string{accessForA}, id: []string{idB, idA}}
		info, err := env.auth.Authenticate(ctx, provider)
		requireBoundPairRejected(t, info, err)
	})

	t.Run("matching subjects keep the checked id token and delegated permissions", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, httpProvider(accessForA, idA, "Bearer ", "Bearer "))
		requireAuthorizedAs(t, info, err, "user:1", "user:1", "id-a@example.com")
		require.Equal(t, bindingNamespace, info.GetNamespace())
	})

	t.Run("reread after a match still uses the checked id token", func(t *testing.T) {
		provider := &sequencedTokenProvider{access: []string{accessForA}, id: []string{idA, idB}}
		info, err := env.auth.Authenticate(ctx, provider)
		requireAuthorizedAs(t, info, err, "user:1", "user:1", "id-a@example.com")
	})

	t.Run("matching service account", func(t *testing.T) {
		id := env.idToken(t, "service-account:9", authn.IDTokenClaims{
			Identifier: "9",
			Type:       types.TypeServiceAccount,
			Namespace:  bindingNamespace,
			Email:      "id-sa@example.com",
		})
		info, err := env.auth.Authenticate(ctx, grpcProvider(serviceAccountAccess, id))
		requireAuthorizedAs(t, info, err, "service-account:9", "service-account:9", "id-sa@example.com")
	})

	t.Run("matching anonymous", func(t *testing.T) {
		id := env.idToken(t, "anonymous:anon", authn.IDTokenClaims{
			Identifier: "anon",
			Type:       types.TypeAnonymous,
			Namespace:  bindingNamespace,
		})
		info, err := env.auth.Authenticate(ctx, grpcProvider(anonymousAccess, id))
		require.NoError(t, err)
		require.Equal(t, "anonymous:anon", info.GetSubject())
		require.Equal(t, "anonymous:anon", info.GetUID())
		require.Equal(t, types.TypeAnonymous, info.GetIdentityType())
		decision := authz.CheckServicePermissions(info, bindingGroup, bindingResource, bindingVerb)
		require.False(t, decision.ServiceCall)
		require.True(t, decision.Allowed)
	})

	t.Run("matching innermost actor", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, grpcProvider(nested, idA))
		requireAuthorizedAs(t, info, err, "user:1", "user:1", "id-a@example.com")
	})

	t.Run("access policy actor is not an identity binding", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, grpcProvider(policyActor, idB))
		requireAuthorizedAs(t, info, err, "user:2", "user:2", "user-b@example.com")
	})

	t.Run("no actor still accepts an id token", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, httpProvider(noActor, idB, "Bearer ", "Bearer "))
		requireAuthorizedAs(t, info, err, "user:2", "user:2", "user-b@example.com")
	})

	t.Run("access token alone keeps the actor", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, httpProvider(accessForA, "", "", ""))
		require.NoError(t, err)
		require.Equal(t, "user:1", info.GetSubject())
		require.Equal(t, "user:1", info.GetUID())
		require.Equal(t, "actor-a@example.com", info.GetEmail())
		require.Equal(t, []string{bindingPermission}, info.GetTokenDelegatedPermissions())
		decision := authz.CheckServicePermissions(info, bindingGroup, bindingResource, bindingVerb)
		require.False(t, decision.ServiceCall)
		require.True(t, decision.Allowed)
	})

	t.Run("namespace mismatch still rejected when subjects match", func(t *testing.T) {
		narrow := env.accessToken(t, "stacks-2", userA)
		info, err := env.auth.Authenticate(ctx, grpcProvider(narrow, idA))
		require.Error(t, err)
		require.Nil(t, info)
	})

	t.Run("signature mismatch still rejected when subjects match", func(t *testing.T) {
		info, err := env.auth.Authenticate(ctx, grpcProvider(accessForA, badSignatureID))
		require.Error(t, err)
		require.Nil(t, info)
	})
}

func TestNewIDTokenAuthInfoBindsActorSubject(t *testing.T) {
	delegated := []string{bindingPermission}
	access := func(actor *authn.ActorClaims) authn.Claims[authn.AccessTokenClaims] {
		return authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "access-policy:svc", Audience: []string{bindingAudience}},
			Rest: authn.AccessTokenClaims{
				Namespace:            bindingNamespace,
				DelegatedPermissions: delegated,
				Permissions:          []string{bindingServicePerm},
				Actor:                actor,
			},
		}
	}
	idClaims := func(subject, identifier, email string, typ types.IdentityType) *authn.Claims[authn.IDTokenClaims] {
		return &authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: subject},
			Rest: authn.IDTokenClaims{
				Identifier: identifier,
				Type:       typ,
				Namespace:  bindingNamespace,
				Email:      email,
			},
		}
	}

	t.Run("mismatched user is not an identity", func(t *testing.T) {
		info := authn.NewIDTokenAuthInfo(access(userActor("user:1", "1", "actor-a@example.com")), idClaims("user:2", "2", "user-b@example.com", types.TypeUser))
		if info != nil {
			decision := authz.CheckServicePermissions(info, bindingGroup, bindingResource, bindingVerb)
			t.Fatalf("NewIDTokenAuthInfo subject %q uid %q delegated %v allowed %v; mismatched identity actor must not produce an AuthInfo",
				info.GetSubject(), info.GetUID(), info.GetTokenDelegatedPermissions(), decision.Allowed)
		}
	})

	t.Run("mismatched innermost actor is not an identity", func(t *testing.T) {
		actor := &authn.ActorClaims{
			Subject: "user:2",
			IDTokenClaims: authn.IDTokenClaims{
				Identifier: "outer",
				Type:       types.TypeAccessPolicy,
			},
			Actor: userActor("user:1", "1", "actor-a@example.com"),
		}
		info := authn.NewIDTokenAuthInfo(access(actor), idClaims("user:2", "2", "user-b@example.com", types.TypeUser))
		require.Nil(t, info)
	})

	t.Run("service account and anonymous actors bind too", func(t *testing.T) {
		info := authn.NewIDTokenAuthInfo(
			access(identityActor("service-account:9", "9", "sa@example.com", types.TypeServiceAccount)),
			idClaims("user:2", "2", "user-b@example.com", types.TypeUser),
		)
		require.Nil(t, info)

		info = authn.NewIDTokenAuthInfo(
			access(identityActor("anonymous:anon", "anon", "", types.TypeAnonymous)),
			idClaims("user:2", "2", "user-b@example.com", types.TypeUser),
		)
		require.Nil(t, info)
	})

	t.Run("matching subject keeps id token claims and delegated permissions", func(t *testing.T) {
		info := authn.NewIDTokenAuthInfo(
			access(userActor("user:1", "1", "actor-a@example.com")),
			idClaims("user:1", "1", "id-a@example.com", types.TypeUser),
		)
		requireAuthorizedAs(t, info, nil, "user:1", "user:1", "id-a@example.com")
	})

	t.Run("nil id token still uses the actor", func(t *testing.T) {
		info := authn.NewIDTokenAuthInfo(access(userActor("user:1", "1", "actor-a@example.com")), nil)
		require.NotNil(t, info)
		require.Equal(t, "user:1", info.GetSubject())
		require.Equal(t, "user:1", info.GetUID())
		require.Equal(t, "actor-a@example.com", info.GetEmail())
		require.Equal(t, delegated, info.GetTokenDelegatedPermissions())
	})

	t.Run("non identity actor still accepts the id token", func(t *testing.T) {
		actor := &authn.ActorClaims{
			Subject: "access-policy:other",
			IDTokenClaims: authn.IDTokenClaims{
				Identifier: "other",
				Type:       types.TypeAccessPolicy,
			},
		}
		info := authn.NewIDTokenAuthInfo(access(actor), idClaims("user:2", "2", "user-b@example.com", types.TypeUser))
		requireAuthorizedAs(t, info, nil, "user:2", "user:2", "user-b@example.com")
	})
}
