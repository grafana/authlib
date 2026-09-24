# AGENTS.md

## Cursor Cloud specific instructions

`authlib` is a pure Go library (shared authn/authz SDK). It has **no runtime services** and
needs nothing beyond Go. Standard commands are in `README.md`; notes below cover non-obvious caveats.

- It is a **multi-module `go.work`** workspace (`.` and `./types`). `go build ./...` /
  `go test ./...` from the root only cover the root module; run the `types` module separately:
  `cd types && go test ./...`.
- `GOTOOLCHAIN=auto` auto-downloads the Go version pinned in `go.mod`; no manual Go install needed.
- Protobuf codegen uses `buf` (`buf generate`, `buf format`); `buf` is not installed by default
  and is only needed when regenerating proto code.
- Known pre-existing failures (unrelated to environment): `types` `TestParseNamespace` has two
  failing subcases referencing the deprecated namespace format removed in commit `be091cf`.
