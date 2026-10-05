# Legacy permission enumeration

`types.LegacyAuthzService` is a deprecated compatibility interface for Grafana's
legacy Access Control permission enumeration. New authorization consumers should
use `types.AccessClient` instead of enumerating permissions.

`authz.LegacyClient`, constructed with `authz.NewLegacyClient`, implements it
using the streaming `LegacyAuthzService.LegacyGetUserPermissions` RPC. The service
and all its protobuf messages live in `proto/v1/legacy_authz.proto`, independently
of `AuthzService`. `ClientImpl` does not implement `LegacyAuthzService`, and
`LegacyClient` does not implement `AccessClient` or create a permission cache.
Tracing can be configured with `WithLegacyTracerClientOption`.

This keeps the new legacy interface, client, service registration and protobuf
file removable together. Existing `AuthzService.GetUserPermissions`,
`UserPermissionsClient`, and `AccessClient` contracts remain unchanged for
compatibility; retiring that pre-existing RPC is a separate migration.

## Deployment and trust

This contract is intended for a dedicated embedded Grafana transport. This authlib
change supplies types, bindings and a client, **not** a server implementation or
Grafana routing changes. Standalone implementations must not register
`LegacyAuthzService`. There is no HTTP gateway route.

The `caller` argument is an authenticated service identity (access policy), not
the target user. The client requires the service permission
`authz.grafana.app/legacyuserpermissions:get`; the existing
`authz.grafana.app/userpermissions:get` grant alone is insufficient. Delegated
user identities are rejected, even with the new delegated permission.

These are client-side preflight checks, not server authentication. A caller can
bypass this client. The embedded handler must independently authenticate the
service using its transport, validate the instance namespace and evaluation
scope, and reject untrusted identity assertions. A service grant alone must not
make asserted admin/role/team context acceptable on a standalone server.

Use a dedicated embedded client even when Check/List use a remote AuthZ client.
Do not automatically fall back to another RPC or to local permission loading on
an error or `Unimplemented` response.

## Request contract

- `Namespace` is a concrete tenant namespace (`stacks-N`, `default`, or a valid
  `org-N`). It remains required for global-only evaluation. A wildcard, empty
  namespace, or `org-0` is not a substitute for global scope.
- `GlobalOrg` is the only evaluation-scope selector. When false (including when
  omitted), evaluation uses the namespace's organization ID: 1 for a Cloud stack
  or `default`, and N for `org-N`. When true, evaluation uses org zero for
  instance-global legacy grants. It never authorizes cross-tenant access;
  namespace authorization applies in both cases, and the server checks instance
  ownership. There is no separate organization ID or scope enum to contradict
  the namespace. The Grafana adapter will set this flag from
  `requester.GetOrgID() == 0`; for non-global requests it must select a namespace
  corresponding to the requester's organization.
- `Identity.Type` and the **untyped** `Identity.UID` identify the target together.
  Numeric-looking UIDs are not internal IDs. `InternalID` is optional: absent,
  zero and negative legacy values are transported distinctly, without client
  identity resolution. The handler applies the legacy identity contract.
- `HasUniqueID` preserves legacy cacheability, including synthetic identities.
- `OrgRole`, `IsGrafanaAdmin`, and `TeamIDs` are trusted requester assertions,
  not instructions to resolve the target's current role or memberships from DB.
- Numeric `TeamIDs` supply legacy RBAC memberships. String `Groups` supply the
  target's selected Zanzana contextual groups. The client never substitutes the
  service caller's groups, including when target groups are empty.
- Licensing and instance policy are server dependencies, not request fields.

## Cache and result contract

`ReloadCache` and `SkipZanzanaCache` are independent. `SkipZanzanaCache` bypasses
Zanzana cache reads **and writes**, without requesting a legacy cache refresh.
The client transmits both options unchanged; the embedded loader owns their
implementation and mutation invalidation.

The legacy method does not read, populate or invalidate the authlib client
cache. Every invocation reaches the transport. The existing
`UserPermissionsClient.InvalidateUserPermissions` method is not a server-side
invalidation interface and does not apply to this contract.

The client buffers all chunks until successful EOF. It preserves duplicate
permissions, empty scopes and wildcard strings, and accepts an empty stream as
an empty snapshot. A transport error or malformed response discards all buffered
permissions. Cancellation and deadlines propagate to the RPC; the client cancels
the stream when it returns, including on malformed chunks.

## Compatibility and generation

The service and messages are additive; existing RPC field numbers, methods and
generated `AuthzService` Go interfaces are unchanged. Existing implementations and
fakes require no additional method. Servers that do not register the legacy
service return `Unimplemented`; a separately registered server embedding
`UnimplementedLegacyAuthzServiceServer` also returns `Unimplemented` by default.
Removing the legacy registration does not affect the existing service, even when
both share a connection.

Regenerate with the repository's `buf generate` configuration and run
`buf format --write`. Its pinned plugins produce protobuf/gRPC bindings and
OpenAPI definitions, but no new HTTP path. CI checks regeneration and formatting.

Validation commands from the repository root:

```sh
go test ./...
go test ./types/...
go vet ./... ./types/...
buf breaking --against '.git#ref=origin/main'
```
