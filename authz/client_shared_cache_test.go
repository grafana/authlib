package authz

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/types"
)

// Two ClientImpl values that dial different authorization services and share one
// cache must keep each service's Check, Compile, and GetUserPermissions
// decisions separate. A later read from the second client has to be that
// service's decision for the same subject and request, and the first client's
// own cached decision must stay in place. These tests fail while the cache key
// omits the authorization service.

const (
	sharedCacheAllowTimestamp int64 = 1_700_000_000_000
	sharedCacheDenyTimestamp  int64 = 1_800_000_000_000
	sharedCacheFlipTimestamp  int64 = 1_700_000_000_111
)

func TestClient_SharedCache_CheckDoesNotApplyAnotherServicesAllow(t *testing.T) {
	shared := newSharedAuthzCache()
	orgA := &scriptedAuthz{allowDash1: true, checkTS: sharedCacheAllowTimestamp}
	orgB := &scriptedAuthz{allowDash1: false, checkTS: sharedCacheDenyTimestamp}
	clientA := newClientForAuthzService(t, shared, orgA)
	clientB := newClientForAuthzService(t, shared, orgB)
	req := dash1CheckRequest()

	got, err := clientA.Check(context.Background(), newOnPremUser(), req, "")
	require.NoError(t, err)
	require.True(t, got.Allowed)
	requireZookieTimestamp(t, got.Zookie, sharedCacheAllowTimestamp)
	require.Equal(t, []recordedCheck{dash1RecordedCheck()}, orgA.recordedChecks())

	// A cache miss on A would now be a deny. A hit must stay the original allow.
	orgA.setCheckPolicy(false, sharedCacheFlipTimestamp)

	got, err = clientB.Check(context.Background(), newOnPremUser(), req, "")
	require.NoError(t, err)
	require.False(t, got.Allowed)
	requireZookieTimestamp(t, got.Zookie, sharedCacheDenyTimestamp)
	require.Equal(t, []recordedCheck{dash1RecordedCheck()}, orgB.recordedChecks())

	got, err = clientA.Check(context.Background(), newOnPremUser(), req, "")
	require.NoError(t, err)
	require.True(t, got.Allowed)
	requireZookieTimestamp(t, got.Zookie, sharedCacheAllowTimestamp)
	require.Equal(t, []recordedCheck{dash1RecordedCheck()}, orgA.recordedChecks())
}

func TestClient_SharedCache_CheckDoesNotApplyAnotherServicesDeny(t *testing.T) {
	shared := newSharedAuthzCache()
	orgA := &scriptedAuthz{allowDash1: false, checkTS: sharedCacheDenyTimestamp}
	orgB := &scriptedAuthz{allowDash1: true, checkTS: sharedCacheAllowTimestamp}
	clientA := newClientForAuthzService(t, shared, orgA)
	clientB := newClientForAuthzService(t, shared, orgB)
	req := dash1CheckRequest()

	got, err := clientA.Check(context.Background(), newOnPremUser(), req, "")
	require.NoError(t, err)
	require.False(t, got.Allowed)
	requireZookieTimestamp(t, got.Zookie, sharedCacheDenyTimestamp)
	require.Equal(t, []recordedCheck{dash1RecordedCheck()}, orgA.recordedChecks())

	orgA.setCheckPolicy(true, sharedCacheFlipTimestamp)

	got, err = clientB.Check(context.Background(), newOnPremUser(), req, "")
	require.NoError(t, err)
	require.True(t, got.Allowed)
	requireZookieTimestamp(t, got.Zookie, sharedCacheAllowTimestamp)
	require.Equal(t, []recordedCheck{dash1RecordedCheck()}, orgB.recordedChecks())

	got, err = clientA.Check(context.Background(), newOnPremUser(), req, "")
	require.NoError(t, err)
	require.False(t, got.Allowed)
	requireZookieTimestamp(t, got.Zookie, sharedCacheDenyTimestamp)
	require.Equal(t, []recordedCheck{dash1RecordedCheck()}, orgA.recordedChecks())
}

func TestClient_SharedCache_CompileDoesNotApplyAnotherServicesAllow(t *testing.T) {
	shared := newSharedAuthzCache()
	orgA := &scriptedAuthz{listItems: []string{"dash-1"}, listTS: sharedCacheAllowTimestamp}
	orgB := &scriptedAuthz{listItems: []string{"other-dash"}, listTS: sharedCacheDenyTimestamp}
	clientA := newClientForAuthzService(t, shared, orgA)
	clientB := newClientForAuthzService(t, shared, orgB)
	req := dashboardsListRequest()

	checker, zookie, err := clientA.Compile(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.True(t, checker("dash-1", ""))
	require.False(t, checker("other-dash", ""))
	requireZookieTimestamp(t, zookie, sharedCacheAllowTimestamp)
	require.Equal(t, []recordedList{dashboardsRecordedList()}, orgA.recordedLists())

	orgA.setListPolicy(nil, sharedCacheFlipTimestamp)

	checker, zookie, err = clientB.Compile(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.False(t, checker("dash-1", ""))
	require.True(t, checker("other-dash", ""))
	requireZookieTimestamp(t, zookie, sharedCacheDenyTimestamp)
	require.Equal(t, []recordedList{dashboardsRecordedList()}, orgB.recordedLists())

	checker, zookie, err = clientA.Compile(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.True(t, checker("dash-1", ""))
	require.False(t, checker("other-dash", ""))
	requireZookieTimestamp(t, zookie, sharedCacheAllowTimestamp)
	require.Equal(t, []recordedList{dashboardsRecordedList()}, orgA.recordedLists())
}

func TestClient_SharedCache_CompileDoesNotApplyAnotherServicesDeny(t *testing.T) {
	shared := newSharedAuthzCache()
	orgA := &scriptedAuthz{listItems: nil, listTS: sharedCacheDenyTimestamp}
	orgB := &scriptedAuthz{listItems: []string{"dash-1"}, listTS: sharedCacheAllowTimestamp}
	clientA := newClientForAuthzService(t, shared, orgA)
	clientB := newClientForAuthzService(t, shared, orgB)
	req := dashboardsListRequest()

	checker, zookie, err := clientA.Compile(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.False(t, checker("dash-1", ""))
	requireZookieTimestamp(t, zookie, sharedCacheDenyTimestamp)
	require.Equal(t, []recordedList{dashboardsRecordedList()}, orgA.recordedLists())

	orgA.setListPolicy([]string{"dash-1"}, sharedCacheFlipTimestamp)

	checker, zookie, err = clientB.Compile(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.True(t, checker("dash-1", ""))
	requireZookieTimestamp(t, zookie, sharedCacheAllowTimestamp)
	require.Equal(t, []recordedList{dashboardsRecordedList()}, orgB.recordedLists())

	checker, zookie, err = clientA.Compile(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.False(t, checker("dash-1", ""))
	requireZookieTimestamp(t, zookie, sharedCacheDenyTimestamp)
	require.Equal(t, []recordedList{dashboardsRecordedList()}, orgA.recordedLists())
}

func TestClient_SharedCache_GetUserPermissionsDoesNotApplyAnotherServicesSnapshot(t *testing.T) {
	shared := newSharedAuthzCache()
	orgAPerms := []types.Permission{{Action: "dashboards:read", Scope: "dashboards:uid:dash-1"}}
	orgBPerms := []types.Permission{{Action: "folders:read", Scope: "folders:uid:fold-1"}}
	orgA := &scriptedAuthz{perms: toProtoPermissions(orgAPerms)}
	orgB := &scriptedAuthz{perms: toProtoPermissions(orgBPerms)}
	clientA := newClientForAuthzService(t, shared, orgA)
	clientB := newClientForAuthzService(t, shared, orgB)
	req := types.GetUserPermissionsRequest{Namespace: "default"}

	got, err := clientA.GetUserPermissions(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.Equal(t, orgAPerms, got.Permissions)
	require.Equal(t, []recordedUserPermissions{defaultRecordedUserPermissions()}, orgA.recordedUserPermissions())

	orgA.setPermissions(toProtoPermissions([]types.Permission{{Action: "flipped:read", Scope: "flipped"}}))

	got, err = clientB.GetUserPermissions(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.Equal(t, orgBPerms, got.Permissions)
	require.Equal(t, []recordedUserPermissions{defaultRecordedUserPermissions()}, orgB.recordedUserPermissions())

	got, err = clientA.GetUserPermissions(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.Equal(t, orgAPerms, got.Permissions)
	require.Equal(t, []recordedUserPermissions{defaultRecordedUserPermissions()}, orgA.recordedUserPermissions())
}

func TestClient_SharedCache_InvalidateUserPermissionsDoesNotEvictAnotherService(t *testing.T) {
	shared := newSharedAuthzCache()
	orgAPerms := []types.Permission{{Action: "dashboards:read", Scope: "dashboards:uid:dash-1"}}
	orgA := &scriptedAuthz{perms: toProtoPermissions(orgAPerms)}
	orgB := &scriptedAuthz{perms: toProtoPermissions([]types.Permission{{Action: "folders:read", Scope: "folders:uid:fold-1"}})}
	clientA := newClientForAuthzService(t, shared, orgA)
	clientB := newClientForAuthzService(t, shared, orgB)
	req := types.GetUserPermissionsRequest{Namespace: "default"}

	got, err := clientA.GetUserPermissions(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.Equal(t, orgAPerms, got.Permissions)

	orgA.setPermissions(toProtoPermissions([]types.Permission{{Action: "flipped:read", Scope: "flipped"}}))

	require.NoError(t, clientB.InvalidateUserPermissions(context.Background(), newOnPremUser(), req))

	got, err = clientA.GetUserPermissions(context.Background(), newOnPremUser(), req)
	require.NoError(t, err)
	require.Equal(t, orgAPerms, got.Permissions)
	require.Equal(t, []recordedUserPermissions{defaultRecordedUserPermissions()}, orgA.recordedUserPermissions())
}

func newSharedAuthzCache() cache.Cache {
	return cache.NewLocalCache(cache.Config{
		Expiry:          5 * time.Minute,
		CleanupInterval: 10 * time.Minute,
	})
}

func newClientForAuthzService(t *testing.T, shared cache.Cache, svc authzv1.AuthzServiceServer) *ClientImpl {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	authzv1.RegisterAuthzServiceServer(server, svc)
	go func() {
		_ = server.Serve(lis)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = lis.Close()
	})

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	return NewClient(conn, WithCacheClientOption(shared))
}

func newOnPremUser() *authn.AuthInfo {
	return authn.NewIDTokenAuthInfo(
		authn.Claims[authn.AccessTokenClaims]{
			Claims: jwt.Claims{Subject: "service"},
			Rest: authn.AccessTokenClaims{
				Namespace: "default",
				DelegatedPermissions: []string{
					"dashboards.grafana.app/dashboards:get",
					"authz.grafana.app/userpermissions:get",
				},
			},
		},
		&authn.Claims[authn.IDTokenClaims]{
			Claims: jwt.Claims{Subject: "user:1"},
			Rest: authn.IDTokenClaims{
				Identifier: "1",
				Type:       types.TypeUser,
				Namespace:  "default",
				Groups:     []string{"editors"},
			},
		},
	)
}

func dash1CheckRequest() types.CheckRequest {
	return types.CheckRequest{
		Namespace: "default",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Verb:      "get",
		Name:      "dash-1",
	}
}

func dashboardsListRequest() types.ListRequest {
	return types.ListRequest{
		Namespace: "default",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Verb:      "get",
	}
}

func requireZookieTimestamp(t *testing.T, zookie types.Zookie, timestamp int64) {
	t.Helper()
	require.NotNil(t, zookie)
	require.True(t, zookie.IsFresherThan(time.UnixMilli(timestamp-1)))
	require.False(t, zookie.IsFresherThan(time.UnixMilli(timestamp)))
}

type recordedCheck struct {
	Subject     string
	Teams       []string
	Verb        string
	Group       string
	Resource    string
	Namespace   string
	Name        string
	Folder      string
	Subresource string
	Path        string
}

func sameCheck(got, want recordedCheck) bool {
	return got.Subject == want.Subject &&
		slices.Equal(got.Teams, want.Teams) &&
		got.Verb == want.Verb &&
		got.Group == want.Group &&
		got.Resource == want.Resource &&
		got.Namespace == want.Namespace &&
		got.Name == want.Name &&
		got.Folder == want.Folder &&
		got.Subresource == want.Subresource &&
		got.Path == want.Path
}

func dash1RecordedCheck() recordedCheck {
	return recordedCheck{
		Subject:   "user:1",
		Teams:     []string{"editors"},
		Verb:      "get",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Namespace: "default",
		Name:      "dash-1",
	}
}

type recordedList struct {
	Subject   string
	Teams     []string
	Verb      string
	Group     string
	Resource  string
	Namespace string
}

func dashboardsRecordedList() recordedList {
	return recordedList{
		Subject:   "user:1",
		Teams:     []string{"editors"},
		Verb:      "get",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Namespace: "default",
	}
}

type recordedUserPermissions struct {
	Subject   string
	Teams     []string
	Namespace string
}

func defaultRecordedUserPermissions() recordedUserPermissions {
	return recordedUserPermissions{
		Subject:   "user:1",
		Teams:     []string{"editors"},
		Namespace: "default",
	}
}

func toProtoPermissions(perms []types.Permission) []*authzv1.UserPermission {
	out := make([]*authzv1.UserPermission, 0, len(perms))
	for _, perm := range perms {
		out = append(out, &authzv1.UserPermission{Action: perm.Action, Scope: perm.Scope})
	}
	return out
}

// scriptedAuthz is an authorization service whose Check allow, list items, and
// permission snapshot are fixed until the test changes them. Check allows
// dash-1 only when allowDash1 is set and the request is that exact object.
type scriptedAuthz struct {
	authzv1.UnimplementedAuthzServiceServer

	mu         sync.Mutex
	allowDash1 bool
	checkTS    int64
	listItems  []string
	listTS     int64
	perms      []*authzv1.UserPermission

	checks []recordedCheck
	lists  []recordedList
	users  []recordedUserPermissions
}

func (s *scriptedAuthz) setCheckPolicy(allow bool, timestamp int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowDash1 = allow
	s.checkTS = timestamp
}

func (s *scriptedAuthz) setListPolicy(items []string, timestamp int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listItems = append([]string(nil), items...)
	s.listTS = timestamp
}

func (s *scriptedAuthz) setPermissions(perms []*authzv1.UserPermission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perms = perms
}

func (s *scriptedAuthz) recordedChecks() []recordedCheck {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedCheck(nil), s.checks...)
}

func (s *scriptedAuthz) recordedLists() []recordedList {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedList(nil), s.lists...)
}

func (s *scriptedAuthz) recordedUserPermissions() []recordedUserPermissions {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedUserPermissions(nil), s.users...)
}

func (s *scriptedAuthz) Check(_ context.Context, in *authzv1.CheckRequest) (*authzv1.CheckResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	recorded := recordedCheck{
		Subject:     in.GetSubject(),
		Teams:       append([]string(nil), in.GetTeams()...),
		Verb:        in.GetVerb(),
		Group:       in.GetGroup(),
		Resource:    in.GetResource(),
		Namespace:   in.GetNamespace(),
		Name:        in.GetName(),
		Folder:      in.GetFolder(),
		Subresource: in.GetSubresource(),
		Path:        in.GetPath(),
	}
	s.checks = append(s.checks, recorded)

	allowed := s.allowDash1 && sameCheck(recorded, dash1RecordedCheck())
	return &authzv1.CheckResponse{
		Allowed: allowed,
		Zookie:  &authzv1.Zookie{Timestamp: s.checkTS},
	}, nil
}

func (s *scriptedAuthz) List(_ context.Context, in *authzv1.ListRequest) (*authzv1.ListResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lists = append(s.lists, recordedList{
		Subject:   in.GetSubject(),
		Teams:     append([]string(nil), in.GetTeams()...),
		Verb:      in.GetVerb(),
		Group:     in.GetGroup(),
		Resource:  in.GetResource(),
		Namespace: in.GetNamespace(),
	})

	return &authzv1.ListResponse{
		Items:  append([]string(nil), s.listItems...),
		Zookie: &authzv1.Zookie{Timestamp: s.listTS},
	}, nil
}

func (s *scriptedAuthz) GetUserPermissions(req *authzv1.GetUserPermissionsRequest, stream authzv1.AuthzService_GetUserPermissionsServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users = append(s.users, recordedUserPermissions{
		Subject:   req.GetSubject(),
		Teams:     append([]string(nil), req.GetTeams()...),
		Namespace: req.GetNamespace(),
	})

	perms := make([]*authzv1.UserPermission, 0, len(s.perms))
	for _, perm := range s.perms {
		perms = append(perms, &authzv1.UserPermission{Action: perm.GetAction(), Scope: perm.GetScope()})
	}
	return stream.Send(&authzv1.GetUserPermissionsResponse{Permissions: perms})
}
