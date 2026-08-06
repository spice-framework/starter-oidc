# Dependency review: go-oidc

- Decision: approved for the isolated `github.com/spice-framework/starter-oidc`
  module.
- Version: `github.com/coreos/go-oidc/v3` v3.20.0.
- Upstream: <https://github.com/coreos/go-oidc>.
- License: Apache-2.0; retained in vendored module license files.
- Maintenance: established OIDC integration used by the Go ecosystem; v3.20.0
  was released July 8, 2026 and requires Go 1.25.
- Security: the adapter exposes no skip-issuer, skip-audience, skip-expiry, or
  skip-signature switches. RFC 9068 token typing prevents ID-token
  substitution. Algorithms are allowlisted, discovery and JWKS are HTTPS-only,
  redirects are refused, and responses and tokens are bounded. The reachable
  graph remains subject to gosec and govulncheck.
- Cancellation: verification accepts the request context. Explicit discovery
  requires a timed caller-owned client and propagates cancellation through both
  metadata and JWKS requests.
- Observability: decisions use bounded reason classes and never contain raw
  tokens, subjects, upstream errors, roles, or scopes.
- Configuration: exact issuer, audience, claim names, algorithm allowlist, and
  token size are constructor inputs. There is no environment lookup or global
  verifier.
- Transitive scope: `go-jose/v4` and `golang.org/x/oauth2`; no provider SDK,
  session store, reverse proxy, browser flow, or server framework is adopted.
- Spice compatibility: the module selects the provisional minimum. The strict
  repository compatibility manifest and isolated CI matrix verify distinct
  minimum and current revisions with exact MVS selection; the starter manifest
  independently requires the exact Spice starter API.

Primary references:

- <https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc>
- <https://github.com/coreos/go-oidc>
- <https://openid.net/specs/openid-connect-core-1_0.html>
- <https://www.rfc-editor.org/rfc/rfc9068.html>

## Build-only dependencies: Spice release tools

- Decision: approved as the repository-authorized release signer, renderer,
  and independent verifier.
- Signer version: `github.com/spice-framework/development`
  `v0.0.0-20260806121906-963bb6676069`.
- Signer tool: `github.com/spice-framework/development/cmd/spice-dev` through the
  standard Go `tool` directive; invocations always use the full package path.
- Verifier version: `github.com/spice-framework/toolchain`
  `v0.0.0-20260806054457-a83d9b58034c`.
- Verifier tool:
  `github.com/spice-framework/toolchain/cmd/spice-library-release-verify`.
- License: Apache-2.0, with its notice retained in `vendor`.
- Runtime scope: none. Product packages do not import the development module,
  and released applications acquire no runtime dependency on it.
- Dependency graph: the tool participates in normal Go minimal-version
  selection. That build-time coupling is accepted and visible in `go.mod`,
  `go.sum`, and `vendor/modules.txt`; no parallel tool registry is introduced.
- Integrity and network behavior: the exact pseudo-version is pinned and
  checksummed. Release parity runs with `GOWORK=off`, `GOPROXY=off`,
  `GOTOOLCHAIN=local`, and `GOFLAGS=-mod=vendor`, so it cannot select an ambient
  checkout, upgrade itself, or download dependencies.
- Security: the native build tool is trusted repository code, reads the exact
  committed Git graph, and writes only to a caller-supplied temporary output
  directory. The rehearsal emits no signatures or signing material.
- Maintenance: the protected central workflow owns production. The retained
  local builder remains only as the dual-builder parity oracle and is not
  removed by this cutover.
