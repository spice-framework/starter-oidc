# Starter OIDC implementation contract

This repository owns the independently versioned OpenID Connect resource-server
integration for Spice. Work directly on local `main` in bounded commits. Fetch
before editing and immediately before pushing; never overwrite unexpected
remote work.

Go 1.26.5 is mandatory. Every product change must preserve exact issuer and
audience verification, access-token typing, caller-owned contexts and HTTP
clients, HTTPS-only discovery and JWKS retrieval, bounded response and token
sizes, redirect refusal, and secret-safe diagnostics and observations. There
must be no global verifier, environment lookup, hidden dependency download, or
switch that disables signature, issuer, audience, or expiry checks.

Release-parity work must preserve the exact `spice-dev` tool version authorized
by the root `go.mod`, invoke its full package path, and run both central and
retained rehearsals with workspace and network resolution disabled in vendor
mode. The retained repository builder and signed production workflow remain
authoritative until a separately reviewed signing migration; unsigned parity
must never manufacture signatures or key material.

Add positive and failure-path tests, update public documentation, use focused
checks while iterating, run `make verify` once on the exact final tree, and push
only a green commit. Deterministic local TLS/JWKS acceptance is mandatory and
must not contact an external identity provider. Never hand-edit vendor files.
