# Changelog

All notable changes to Ariadne are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-07-13

Data at scale — feed the moat.

### Added
- **Crypto-ATM geolocation intelligence** — a worldwide registry of physical crypto
  ATMs (operator, street address, latitude/longitude) synced from OpenStreetMap via
  the keyless Overpass API. New `ariadne atm-sync` and `ariadne atm` (query by
  proximity, operator, or list operators). When a trace's cash-out is an ATM
  operator, the report and court-ready expert statement list that operator's
  candidate physical kiosks — honestly captioned: on-chain data names the operator,
  the exact machine + customer + CCTV come from the operator under lawful process.
- **Attribution at scale** — the etherscan-labels ingestion now classifies the full
  ~30k-address, 500+ tag space (exchanges, thousands of DEX/DeFi services, bridges,
  gambling, mixers, ATMs, frozen, sanctioned, scam) instead of a handful of tags,
  taking `update-intel` from ~20k to ~26k labels and sharply improving the ability
  to *name* an EVM cash-out.
- **`atm` and `gambling`** label categories; crypto-ATM and gambling addresses are
  treated as terminal cash-out points and graded accordingly (ATM = FATF high-risk
  off-ramp with a physical location).
- Web console surfaces a "Crypto-ATM cash-out — physical locations" panel.

## [0.2.0] — 2026-07-12

A major upgrade toward government-grade financial-crime intelligence. Every
addition is real and tested; nothing offers a capability it cannot back with data.

### Added — forensic defensibility
- **Selectable, documented taint models** — poison / haircut / FIFO (*Clayton's
  Case*), chosen with `--taint-model`; every report records which model produced it.
- **Ed25519-signed evidence bundles** — real asymmetric signatures, a per-
  investigation **chain of custody** drawn from the provenance cache, and a
  **reproducibility manifest**. `ariadne verify-evidence` checks a bundle offline.
- **Court-ready expert report** — `--report` emits a standardized Markdown expert
  statement with a first-class Limitations section.

### Added — analytical depth
- **Exchange deposit-address discovery** — names an unlabelled cash-out by its
  sweep pattern; writes back to a new **versioned attribution store**.
- **Graph link-analysis** — shortest path, betweenness centrality, community
  detection over the accumulated flow graph (`ariadne graph`).
- **Cross-chain / bridge correlation** — match deposit↔withdrawal by amount + time
  (`ariadne correlate`).
- **Money-laundering typology + composite risk engine** — explainable, FATF-aligned.
- **Sanctions / illicit-exposure screening** — compliance verdict with hop-distance
  and exposed value (`ariadne screen`).
- **Temporal / behavioural fingerprinting** — likely operator timezone, velocity,
  burstiness, dormancy (`ariadne timeline`).
- **Change-address clustering** — a second entity-resolution pillar beyond common-input.
- **Stablecoin-issuer freeze** feed and label category.

### Added — scale, security, opsec
- **Concurrent tracing** (`--workers`) with a thread-safe cache and rate-limit-aware
  throttle; deterministic output.
- **Opsec**: route all provider queries through a SOCKS/Tor proxy (`ARIADNE_PROXY`)
  or a self-hosted indexer (`ARIADNE_ENDPOINT_<CHAIN>`).
- **Honest chain gating** — LTC/DOGE/XMR disabled by default (no hollow surface).
- **Deterministic adversarial detection suite** (`ariadne adversarial`).
- **CI** (ruff + pytest across Python 3.10–3.12).

### Fixed
- **Web RBAC privilege escalation** — roles are now bound to tokens server-side with
  constant-time comparison; the spoofable `X-Role` header no longer grants access.
- **EVM taint denominator** — sums real ERC-20 inflow instead of collapsing toward
  1.0 on USDT/ETH.
- **Service detection** is label-first; an illicit-labelled busy address is no longer
  downgraded to a benign "service".

### Security
- Ed25519 signing keys are git-ignored; the private key is never committed.

## [0.1.0]
- Initial release: multi-hop tracing, taint, attribution, clustering, live
  monitoring, tamper-evident knowledge base, web console, and accuracy harnesses.
