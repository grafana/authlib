package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/cache"
)

const (
	searchCacheAction = "dashboards:read"
	searchCachePrefix = "dashboards"

	// Obvious placeholders. These are not credentials.
	placeholderServiceCredential      = "placeholder-service-credential"
	placeholderServiceCredentialOther = "placeholder-service-credential-other"
)

// Shared permission-search entries must follow the Grafana API URL and the
// service credential that produced them. These tests fail while the cache key
// is only the action and the namespaced id.
func TestSharedPermissionSearchCache(t *testing.T) {
	resFromA := Resource{Kind: "dashboards", Attr: "uid", ID: "from-a"}
	resFromB := Resource{Kind: "dashboards", Attr: "uid", ID: "from-b"}
	unrelated := Resource{Kind: "dashboards", Attr: "uid", ID: "unrelated"}

	cases := []struct {
		name    string
		subject string
		pair    func(t *testing.T, subject string) (privileged, limited *grafanaStub)
	}{
		{
			name:    "different API URLs and the same service credential",
			subject: "user:1",
			pair: func(t *testing.T, subject string) (*grafanaStub, *grafanaStub) {
				return differentAPIURLs(t, subject, placeholderServiceCredential, placeholderServiceCredential, resFromA, resFromB)
			},
		},
		{
			name:    "same API URL and different service credentials",
			subject: "user:1",
			pair: func(t *testing.T, subject string) (*grafanaStub, *grafanaStub) {
				return sameAPIURL(t, subject, placeholderServiceCredential, placeholderServiceCredentialOther, resFromA, resFromB)
			},
		},
		{
			name:    "different API URLs and different service credentials",
			subject: "user:1",
			pair: func(t *testing.T, subject string) (*grafanaStub, *grafanaStub) {
				return differentAPIURLs(t, subject, placeholderServiceCredential, placeholderServiceCredentialOther, resFromA, resFromB)
			},
		},
		{
			name:    "service-account subject on different API URLs",
			subject: "service-account:1",
			pair: func(t *testing.T, subject string) (*grafanaStub, *grafanaStub) {
				return differentAPIURLs(t, subject, placeholderServiceCredential, placeholderServiceCredential, resFromA, resFromB)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("HasAccess", func(t *testing.T) {
				privileged, limited := tc.pair(t, tc.subject)
				shared := newSharedSearchCache()
				first := enforcementClient(t, privileged, shared)
				second := enforcementClient(t, limited, shared)

				allowed, err := first.HasAccess(context.Background(), privileged.idToken, searchCacheAction, resFromA, unrelated)
				require.NoError(t, err)
				require.True(t, allowed, "privileged instance grants from-a")

				allowed, err = second.HasAccess(context.Background(), limited.idToken, searchCacheAction, resFromA, unrelated)
				require.NoError(t, err)
				require.False(t, allowed, "limited instance does not grant from-a")
				require.GreaterOrEqual(t, limited.searchHits.Load(), int32(1), "limited instance must be queried")

				allowed, err = second.HasAccess(context.Background(), limited.idToken, searchCacheAction, resFromB, unrelated)
				require.NoError(t, err)
				require.True(t, allowed, "limited instance grants from-b")
			})

			t.Run("HasAccess single resource", func(t *testing.T) {
				privileged, limited := tc.pair(t, tc.subject)
				shared := newSharedSearchCache()
				first := enforcementClient(t, privileged, shared)
				second := enforcementClient(t, limited, shared)

				allowed, err := first.HasAccess(context.Background(), privileged.idToken, searchCacheAction, resFromA)
				require.NoError(t, err)
				require.True(t, allowed)

				allowed, err = second.HasAccess(context.Background(), limited.idToken, searchCacheAction, resFromA)
				require.NoError(t, err)
				require.False(t, allowed, "a single-resource check uses the scope in the key and still must not reuse the other instance")
				require.GreaterOrEqual(t, limited.searchHits.Load(), int32(1))

				allowed, err = second.HasAccess(context.Background(), limited.idToken, searchCacheAction, resFromB)
				require.NoError(t, err)
				require.True(t, allowed)
			})

			t.Run("Compile", func(t *testing.T) {
				privileged, limited := tc.pair(t, tc.subject)
				shared := newSharedSearchCache()
				first := enforcementClient(t, privileged, shared)
				second := enforcementClient(t, limited, shared)

				checker, err := first.Compile(context.Background(), privileged.idToken, searchCacheAction, "dashboards")
				require.NoError(t, err)
				require.True(t, checker(resFromA))
				require.False(t, checker(resFromB))

				checker, err = second.Compile(context.Background(), limited.idToken, searchCacheAction, "dashboards")
				require.NoError(t, err)
				require.False(t, checker(resFromA), "limited instance does not grant from-a")
				require.True(t, checker(resFromB), "limited instance grants from-b")
				require.GreaterOrEqual(t, limited.searchHits.Load(), int32(1), "limited instance must be queried")
			})

			t.Run("LookupResources", func(t *testing.T) {
				privileged, limited := tc.pair(t, tc.subject)
				shared := newSharedSearchCache()
				first := enforcementClient(t, privileged, shared)
				second := enforcementClient(t, limited, shared)

				got, err := first.LookupResources(context.Background(), privileged.idToken, searchCacheAction)
				require.NoError(t, err)
				require.ElementsMatch(t, []Resource{resFromA}, got)

				got, err = second.LookupResources(context.Background(), limited.idToken, searchCacheAction)
				require.NoError(t, err)
				require.ElementsMatch(t, []Resource{resFromB}, got)
				require.GreaterOrEqual(t, limited.searchHits.Load(), int32(1), "limited instance must be queried")
			})

			t.Run("Search", func(t *testing.T) {
				privileged, limited := tc.pair(t, tc.subject)
				shared := newSharedSearchCache()
				first := enforcementClient(t, privileged, shared)
				second := enforcementClient(t, limited, shared)

				got := searchPermissions(t, first, searchQuery{Action: searchCacheAction, IdToken: privileged.idToken})
				require.Equal(t, []string{resFromA.Scope()}, got[searchCacheAction])

				got = searchPermissions(t, second, searchQuery{Action: searchCacheAction, IdToken: limited.idToken})
				require.Equal(t, []string{resFromB.Scope()}, got[searchCacheAction])
				require.GreaterOrEqual(t, limited.searchHits.Load(), int32(1), "limited instance must be queried")
			})

			t.Run("WithSearchByPrefix", func(t *testing.T) {
				privileged, limited := tc.pair(t, tc.subject)
				shared := newSharedSearchCache()
				first := enforcementClient(t, privileged, shared, WithSearchByPrefix(searchCachePrefix))
				second := enforcementClient(t, limited, shared, WithSearchByPrefix(searchCachePrefix))

				allowed, err := first.HasAccess(context.Background(), privileged.idToken, searchCacheAction, resFromA)
				require.NoError(t, err)
				require.True(t, allowed)

				allowed, err = second.HasAccess(context.Background(), limited.idToken, searchCacheAction, resFromA)
				require.NoError(t, err)
				require.False(t, allowed)
				require.GreaterOrEqual(t, limited.searchHits.Load(), int32(1))

				allowed, err = second.HasAccess(context.Background(), limited.idToken, searchCacheAction, resFromB)
				require.NoError(t, err)
				require.True(t, allowed)

				checker, err := second.Compile(context.Background(), limited.idToken, searchCacheAction, "dashboards")
				require.NoError(t, err)
				require.False(t, checker(resFromA))
				require.True(t, checker(resFromB))

				resources, err := second.LookupResources(context.Background(), limited.idToken, searchCacheAction)
				require.NoError(t, err)
				require.ElementsMatch(t, []Resource{resFromB}, resources)

				got := searchPermissions(t, second, searchQuery{ActionPrefix: searchCachePrefix, IdToken: limited.idToken})
				require.Equal(t, []string{resFromB.Scope()}, got[searchCacheAction])
			})
		})
	}
}

func newSharedSearchCache() cache.Cache {
	return cache.NewLocalCache(cache.Config{
		Expiry:          time.Minute,
		CleanupInterval: time.Minute,
	})
}

func enforcementClient(t *testing.T, inst *grafanaStub, shared cache.Cache, extra ...ClientOption) *EnforcementClientImpl {
	t.Helper()
	opts := make([]ClientOption, 0, 1+len(extra))
	opts = append(opts, WithCache(shared))
	opts = append(opts, extra...)
	client, err := NewEnforcementClient(Config{
		APIURL:  inst.apiURL,
		Token:   inst.credential,
		JWKsURL: inst.jwksURL,
	}, opts...)
	require.NoError(t, err)
	return client
}

func searchPermissions(t *testing.T, client *EnforcementClientImpl, query searchQuery) permissions {
	t.Helper()
	response, err := client.client.(*searchClientImpl).Search(context.Background(), query)
	require.NoError(t, err)
	require.NotNil(t, response.Data)
	require.Len(t, *response.Data, 1)
	perms, ok := (*response.Data)[1]
	require.True(t, ok)
	return perms
}

type grafanaStub struct {
	apiURL     string
	jwksURL    string
	credential string
	idToken    string
	searchHits *atomic.Int32
}

func differentAPIURLs(t *testing.T, subject, credentialA, credentialB string, resFromA, resFromB Resource) (*grafanaStub, *grafanaStub) {
	t.Helper()
	privileged := startGrafana(t, subject, map[string]permissions{
		credentialA: {searchCacheAction: {resFromA.Scope()}},
	})
	limited := startGrafana(t, subject, map[string]permissions{
		credentialB: {searchCacheAction: {resFromB.Scope()}},
	})
	return privileged.stub(t, credentialA, subject), limited.stub(t, credentialB, subject)
}

func sameAPIURL(t *testing.T, subject, credentialA, credentialB string, resFromA, resFromB Resource) (*grafanaStub, *grafanaStub) {
	t.Helper()
	server := startGrafana(t, subject, map[string]permissions{
		credentialA: {searchCacheAction: {resFromA.Scope()}},
		credentialB: {searchCacheAction: {resFromB.Scope()}},
	})
	return server.stub(t, credentialA, subject), server.stub(t, credentialB, subject)
}

type grafanaServer struct {
	apiURL  string
	jwksURL string
	key     *ecdsa.PrivateKey
	keyID   string
	hits    map[string]*atomic.Int32
}

func (g *grafanaServer) stub(t *testing.T, credential, subject string) *grafanaStub {
	t.Helper()
	hits, ok := g.hits[credential]
	require.True(t, ok)
	return &grafanaStub{
		apiURL:     g.apiURL,
		jwksURL:    g.jwksURL,
		credential: credential,
		idToken:    signSearchIDToken(t, g.key, g.keyID, subject),
		searchHits: hits,
	}
}

func startGrafana(t *testing.T, subject string, permissionsByCredential map[string]permissions) *grafanaServer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyID := "signing-key"

	hits := make(map[string]*atomic.Int32, len(permissionsByCredential))
	bodies := make(map[string][]byte, len(permissionsByCredential))
	for credential, perms := range permissionsByCredential {
		hits[credential] = &atomic.Int32{}
		body, err := json.Marshal(map[string]permissions{"1": perms})
		require.NoError(t, err)
		bodies[credential] = body
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			response, err := json.Marshal(jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{{
					Key:       key.Public(),
					KeyID:     keyID,
					Algorithm: string(jose.ES256),
					Use:       "sig",
				}},
			})
			if err != nil {
				http.Error(w, "jwks", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(response)
		case searchPath:
			credential, ok := serviceCredential(r)
			body, known := bodies[credential]
			if !ok || !known {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			query := r.URL.Query()
			if query.Get("namespacedId") != subject {
				http.Error(w, "namespaced id", http.StatusBadRequest)
				return
			}
			action := query.Get("action")
			prefix := query.Get("actionPrefix")
			if action != searchCacheAction && prefix != searchCachePrefix {
				http.Error(w, "action", http.StatusBadRequest)
				return
			}
			hits[credential].Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	return &grafanaServer{
		apiURL:  server.URL,
		jwksURL: server.URL + "/jwks",
		key:     key,
		keyID:   keyID,
		hits:    hits,
	}
}

func serviceCredential(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return "", false
	}
	return header[len(prefix):], true
}

func signSearchIDToken(t *testing.T, key *ecdsa.PrivateKey, keyID, subject string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"kid": keyID,
			"typ": authn.TokenTypeID,
		},
	})
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject: subject,
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	require.NoError(t, err)
	return token
}
