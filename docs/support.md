# Support and compatibility

| Contract | Current development support |
|---|---|
| Go | Exactly 1.26.5 for development and release verification |
| Minimum Spice | `v0.0.0-20260805175412-383c17744300` |
| Current Spice | `v0.0.0-20260805194120-5eb20b5026e9` |
| Spice starter API | Exact `v1alpha1`; mismatches fail closed |
| go-oidc | `github.com/coreos/go-oidc/v3` v3.20.0 |
| OIDC role | JWT resource server; authorization-code/browser login is not included |
| Operating systems | Windows, Linux, and macOS |
| Architectures | amd64 and arm64 compilation through the public core API |
| Transport | HTTPS-only metadata and JWKS, no redirects, timed caller-owned client |
| Token contract | RFC 9068 `at+jwt`, exact issuer and audience, signature and expiry required |

[`spice-compatibility.json`](../spice-compatibility.json) is the sole preview
compatibility boundary. The committed module selects its provisional minimum;
the current value is a forward-compatibility endpoint, not an unbounded runtime
dependency. The repository-owned compatibility verifier resolves each boundary
through an isolated alternate modfile, requires exact MVS selection, runs vet
and shuffled race tests for every product package with `GOPROXY=off`, and hashes
the repository before and after to prove source, module, and vendor immutability.

Release artifacts are produced only from an exact tagged commit under the
contract in [`releasing.md`](releasing.md). A compromised or missing signing
secret fails a production release; it never falls back to unsigned output.
