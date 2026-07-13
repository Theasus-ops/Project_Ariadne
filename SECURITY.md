# Security Policy

Ariadne is investigative software. A defect can mislead an investigation, and a
vulnerability in a deployed instance can expose the sensitive fact of *who is
being investigated*. We take both seriously.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅         |
| < 1.0   | ❌ (pre-release) |

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting
([Security → Report a vulnerability](https://github.com/Theasus-ops/Project_Ariadne/security/advisories/new))
so the report stays confidential until a fix is available.

Include, where you can:

- the component (CLI, web API, a provider, the evidence/signing path);
- a minimal reproduction and the impact you observed;
- the version / commit and your environment.

We aim to acknowledge within **72 hours** and to agree a coordinated-disclosure
timeline with you. We will credit reporters who want credit.

## Scope — what we especially want to hear about

- **Web API auth bypass.** Roles are bound to bearer tokens server-side and
  compared in constant time; the client-supplied role header is *not* trusted.
  Any way around that is high severity.
- **Evidence integrity.** Anything that lets a tampered trace still verify against
  a signed bundle, or that weakens the Ed25519 signing / chain-of-custody / replay
  digest, undermines the whole point of the tool.
- **Injection** via address input, labels, or provider responses (the address
  validators are the first gate — a bypass that reaches a shell, SQL, the
  filesystem, or the report HTML is in scope).
- **Secret exposure** — the private signing key, tokens, or investigation targets
  leaking into logs, URLs, or committed files.

## Operational hardening (deploying Ariadne safely)

- The web API is **unauthenticated by default** and binds to loopback. Pass
  `--auth-token` / `--auth-tokens` and only bind to a non-loopback address behind
  a trusted network, VPN, or authenticating reverse proxy.
- Prefer the production server: `pip install ariadne-tracer[serve]` (waitress).
- Route provider queries through Tor / a self-hosted indexer (`ARIADNE_PROXY`,
  `ARIADNE_ENDPOINT_<CHAIN>`) so you do not leak investigative targets to public
  block explorers.
- The Ed25519 **private signing key** lives under `keys/` and is git-ignored.
  Never commit it; back it up out of band.
- Run the container as the provided non-root user; mount volumes for `cache/`
  and `knowledge/` rather than baking state into the image.
