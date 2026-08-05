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
- Spice compatibility: the development module pins and verifies the exact core
  commit listed in `docs/support.md`; manifest compatibility fails closed on a
  different Spice starter API.

Primary references:

- <https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc>
- <https://github.com/coreos/go-oidc>
- <https://openid.net/specs/openid-connect-core-1_0.html>
- <https://www.rfc-editor.org/rfc/rfc9068.html>
