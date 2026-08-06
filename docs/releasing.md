# Release contract

starter-oidc releases are ordinary Go module tags plus a small, independently
verifiable artifact set. The repository owns the complete build. No external
release build service, mutable workspace snapshot, or network-resolved package
list participates in artifact construction.

For `v1.2.3`, the release builder produces:

| Artifact | Contract |
|---|---|
| `starter-oidc_1.2.3_source.tar.gz` | Exact tagged Git commit, under one versioned directory |
| `starter-oidc_1.2.3_sbom.spdx.json` | SPDX 2.3 packages from the consistent committed `go.mod`, `go.sum`, and `vendor/modules.txt` graph |
| `checksums.txt` | SHA-256 of the source archive and SBOM, sorted by filename |
| `checksums.txt.sig` | Raw Ed25519 signature of the exact checksum bytes |
| `checksums.txt.pem` | X.509 SubjectPublicKeyInfo PEM for signature verification |

The source archive is reconstructed from the full commit's `git ls-tree`
identity and exact object bytes read through `git cat-file --batch`. It never
uses checkout filters or `git archive`, so `core.autocrlf` and host line-ending
settings cannot alter an artifact. Every tar and gzip timestamp is the source
commit epoch; paths are relative, ownership is zeroed, executable modes and
validated symlinks are preserved, and gzip output is deterministic. Gitlinks
and unsupported modes fail closed. Dirty or untracked workspace files cannot
enter the archive. The SBOM creation time uses the same epoch and contains no
absolute checkout path. Construction fails when committed module selection,
checksums, and vendored versions or replacements disagree; the builder does
not rely on an earlier verifier to detect a stale dependency graph.

## Protected production ceremony

The pinned central workflow validates the exact canonical tag and commit,
repeats `make verify-release` without credentials, renders deterministic
artifacts, signs them, and passes them to a separate verifier before publishing.
The retained repository builder is not part of production.

This repository's reviewed public Ed25519 trust anchor is committed at
`security/release/ed25519-public.pem`. Its SHA-256 fingerprint over the DER
SubjectPublicKeyInfo bytes is
`3e2db973565bc970e30418fc3e343893d8d941f88a7dba82d8c6a2b425216c95`.
Store only the matching private key as the repository Actions secret
`SPICE_LIBRARY_RELEASE_SIGNING_KEY`. Configure protected `release-signing` and
`release-publish` environments for the signing approval and write-capable final
job. Both environments should require the repository's designated reviewers.

Do not create or push a release tag until the matching private signing secret
and both protected environments are configured. Committing the public anchor
does not assert that those controls, a tag, or a release exist. The caller
forwards exactly one explicitly named signing secret; broad `secrets: inherit`
forwarding is forbidden. The reusable workflow references that secret only in
its protected `release-signing` job. Validation, planning, independent
verification, and publishing cannot read it. The workflow fails closed on a
missing key, an anchor mismatch, a moved tag, or independent verification
failure.

## Unsigned dual-builder rehearsal

The application module authorizes an exact central renderer through its
`go.mod` tool directive. `make release-parity` runs that fully qualified tool
and the retained repository builder twice each with `GOWORK=off`,
`GOPROXY=off`, `GOTOOLCHAIN=local`, and `GOFLAGS=-mod=vendor`. It first asks the
central tool for a read-only plan, then renders the plan without resolving an
ambient workspace or downloading a module.

The central signer is the protected production path. The retained repository
builder remains only the parity oracle:

```text
make release-parity
```

Both rehearsals are unsigned and always archive `HEAD`, never working-tree
contents. Their source archives must be byte-identical, each builder must be
byte-deterministic across two runs, both checksum files must verify their own
archive and SBOM, and neither output may contain a signature or public key.

The SBOMs must be semantically identical except for these intentional builder
provenance fields:

- document name (`starter-oidc VERSION` centrally and
  `Spice OIDC starter VERSION` in the retained builder);
- document namespace shape (the central renderer includes `spdx/v1/`);
- organization and tool creators identifying the actual renderer.

Their checksum files consequently differ only in the SBOM digest; the source
archive checksum is identical. Package facts, relationships, creation time,
SPDX contract, and every other decoded field must match exactly. The parity
gate fails closed on any extra artifact, dependency drift, malformed checksum,
or undocumented SBOM difference.

`make verify-release` executes this dual-builder rehearsal after the complete
repository verification contract. The retained command stays in the repository
for that proof but is not called by the production workflow.

## Consumer verification

With OpenSSL 3 and GNU-compatible checksum tooling:

```text
sha256sum -c checksums.txt
openssl pkeyutl -verify -pubin -inkey checksums.txt.pem \
  -rawin -in checksums.txt -sigfile checksums.txt.sig
```

Consumers must authenticate the signature with the reviewed committed
`security/release/ed25519-public.pem`, not an untrusted key downloaded beside
the release. The central signer refuses a private key that does not match that
anchor, and the independent verifier authenticates the complete artifact set
before the protected publish job receives it.
