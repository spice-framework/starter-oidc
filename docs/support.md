# Support and compatibility

| Contract | Current development support |
|---|---|
| Go | Exactly 1.26.6 for development and release verification |
| Minimum Spice | `v0.1.0-preview.4.0.20260814014712-5f535e696300` |
| Current Spice | `v0.1.0-preview.4.0.20260814014712-5f535e696300` |
| Spice starter API | Exact `v1alpha1`; mismatches fail closed |
| go-oidc | `github.com/coreos/go-oidc/v3` v3.20.0 |
| Release signer | `github.com/spice-framework/development/cmd/spice-dev` at `v0.0.0-20260806132124-4c308d1b9fda` |
| Independent verifier | `github.com/spice-framework/toolchain/cmd/spice-library-release-verify` at `v0.0.0-20260806133530-71211498297c` |
| Public trust anchor | [`security/release/ed25519-public.pem`](../security/release/ed25519-public.pem), DER SHA-256 `3e2db973565bc970e30418fc3e343893d8d941f88a7dba82d8c6a2b425216c95` |
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
The pinned central signer and independent verifier are the protected production
path. Windows and Linux CI render the same inert central plan twice under
vendor-only offline resolution and require byte-identical unsigned artifacts.

The committed public trust anchor is reviewed verification material. Its
fingerprint is the SHA-256 digest of the DER SubjectPublicKeyInfo bytes. The
anchor does not establish that a matching private signing secret, protected
release environments, a version tag, or a published release exists.
