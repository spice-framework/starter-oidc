# Support and compatibility

| Contract | Current development support |
|---|---|
| Go | Exactly 1.26.5 for development and release verification |
| Spice | `v0.0.0-20260805185924-ee45e0aa386e` |
| Spice starter API | Exact `spice.starter/v1`; mismatches fail closed |
| go-oidc | `github.com/coreos/go-oidc/v3` v3.20.0 |
| OIDC role | JWT resource server; authorization-code/browser login is not included |
| Operating systems | Windows, Linux, and macOS |
| Architectures | amd64 and arm64 compilation through the public core API |
| Transport | HTTPS-only metadata and JWKS, no redirects, timed caller-owned client |
| Token contract | RFC 9068 `at+jwt`, exact issuer and audience, signature and expiry required |

The first preview tag will define the minimum supported Spice version. Until
then, development commits intentionally declare one exact compatible Spice
commit and fail closed outside that tested combination. Future releases will
test both the published minimum and current supported Spice lines before
raising that floor.
