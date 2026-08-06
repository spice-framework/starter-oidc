# Spice OIDC starter

`github.com/spice-framework/starter-oidc` is the independently versioned,
opt-in OpenID Connect JWT resource-server integration for Spice. Importing
Spice core alone never discovers an issuer or creates a verifier.

```go
server, err := oidc.Discover(ctx, httpClient, oidc.Options{
    Issuer:   configuration.Issuer,
    Audience: configuration.Audience,
})
if err != nil {
    return nil, err
}
authentication, err := server.Middleware(reportWriteFailure)
```

`Discover` is the only constructor that performs network I/O. It requires a
caller-owned HTTP client with a positive timeout, refuses redirects, permits
only HTTPS metadata and JWKS endpoints, and bounds provider responses.
`NewResourceServer` accepts a caller-owned `go-oidc` key set for offline or
custom key delivery. Both paths require exact HTTPS issuer and audience
configuration; signature, issuer, audience, expiry, and RFC 9068 access-token
type checks cannot be disabled.

Authentication creates immutable Spice principals from configured role and
scope claims. Required and optional middleware are instance-owned and contain
no environment lookup, global verifier, hidden discovery, or raw-token logging.
Observers receive only bounded result classes and durations.

## Install

```text
go get github.com/spice-framework/starter-oidc@latest
```

During preview development, applications should pin the exact compatible
revision recorded in [support metadata](docs/support.md). The strict
[`spice-compatibility.json`](spice-compatibility.json) contract declares
distinct minimum and current Spice revisions; no public runtime compatibility
API or hidden version selection is invented.

## Verify

Go 1.26.5 is mandatory:

```text
make check
make acceptance
make compatibility
make release-rehearsal
make verify
make verify-release
```

Acceptance uses only local `httptest` TLS identity-provider endpoints. It
exercises discovery, HTTPS and redirect enforcement, bounded metadata, JWKS
verification, issuer/audience/expiry validation, in-flight cancellation,
middleware behavior, and token-safe failures without contacting an external
identity provider.

The complete verifier checks formatting, module/vendor reproducibility, vet,
allowlisted lint and nil safety, gosec, govulncheck, shuffled race tests, at
least 85% product coverage, strict minimum/current core compatibility, and
offline vendor builds. Compatibility runs through isolated modfiles, requires
exact MVS selection, and proves the repository remains byte-for-byte unchanged.
Release rehearsal runs the exact `spice-dev` tool authorized by `go.mod` twice
from one inert plan, entirely from `vendor` with network and workspace
resolution disabled. It requires byte-identical outputs, canonical checksums,
central-renderer SPDX provenance, and no rehearsal signatures on Windows and
Linux.

See [the dependency review](docs/dependency-review.md) and
[support contract](docs/support.md) before production adoption.

## Releases

Each version tag is an ordinary Go module release. The repository also builds
an exact-commit source archive from exact Git objects, a committed-graph SPDX
2.3 SBOM, SHA-256 checksums, and an Ed25519 signature/public key. Production
mode requires a clean checkout, exact tag, and protected signing key; an
explicit unsigned rehearsal is available for local proof. See
[`docs/releasing.md`](docs/releasing.md) for the artifact and trust contract.
The protected central workflow is the sole release authority. It validates the
candidate without credentials, renders and signs with immutable trusted code,
authenticates the result with an independent verifier, and publishes only after
separate protected approvals.
