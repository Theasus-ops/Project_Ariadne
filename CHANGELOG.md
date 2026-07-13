# Changelog

All notable changes to Ariadne are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.6.0] — 2026-07-13

Provability: reproducibility, measured accuracy, and a filing-ready document — the
currency of accreditation, not more capability.

### Added
- **Deterministic replay** (`ariadne replay`) — re-derives a trace **offline from the
  preserved provenance cache**, verifies every source response still matches its
  sealed SHA-256 (tamper detection), and confirms the re-computed report digest is
  identical to the signed bundle. Providers gained an `offline` mode (cache only,
  never the network). Proven end-to-end: FULLY REPRODUCED on a live WannaCry trace.
- **Accuracy benchmark** (`ariadne benchmark`) — per-category precision / recall /
  FP / FN over a sampled corpus, the honest behavioural recall, and an optional
  Ed25519-signed report (`--report --sign`).
- **PDF expert report** (`ariadne.report.pdf`) — a paginated, headed, court-ready PDF
  emitted alongside the Markdown on `trace --report`. Optional dependency (`fpdf2`),
  with a graceful fallback message when not installed. New `pip install -e ".[pdf]"`.

### Changed
- The reproducibility digest (`evidence.report_digest`) now excludes non-reproducible
  post-analysis enrichments (fiat prices, ATM registry, cross-case knowledge) and the
  `workers` performance knob, so a replay of the on-chain analysis reproduces it exactly.
- The trace report records its chain code, enabling replay to rebuild the exact provider.

## [0.5.0] — 2026-07-13

The platform scales up: more chains, whole-operation reasoning, smarter detection,
and autonomy.

### Added
- **Multi-chain EVM** (`providers/evm.py`) — Polygon, Arbitrum, Base and Optimism
  join Ethereum, each traceable for its native coin and USDT/USDC via keyless
  Blockscout. Every endpoint and stablecoin contract was verified live before
  inclusion (correct, active address — never a look-alike scam token). New chain
  codes: `pol/usdt-pol/usdc-pol`, `arb/usdt-arb/usdc-arb`, `base/usdc-base`,
  `op/usdt-op/usdc-op`. BSC intentionally omitted (no keyless endpoint).
- **Multi-seed investigations** (`core/investigation.py`, `ariadne investigate`) —
  trace many seeds into one combined graph and surface shared infrastructure
  (addresses reached from ≥2 seeds), betweenness hubs, and communities, with a
  signed dossier + GraphML export.
- **Statistical anomaly layer** (`core/anomaly.py`) — explainable behavioural-outlier
  detection using robust median/MAD z-scores, complementing the rule-based scorer;
  each flag names the driving feature and its deviation, framed as "review required".
- **Autopilot** (`monitor/autopilot.py`, `ariadne autopilot`) — an autonomous loop
  that polls the watchlist for movement (optional auto-trace) and refreshes the
  intelligence feeds on a schedule, alerting via console / log / webhook, with
  persisted state.

### Changed
- `EthereumProvider` generalised to any EVM chain (explicit token contract + native
  coin + decimals); fast-fails Blockscout 500s on enormous exchange addresses so
  traces don't stall.

## [0.4.0] — 2026-07-13

From one-shot tracer to a continuous investigation platform.

### Added
- **Fiat valuation** (`enrich/prices.py`) — every amount priced in USD/EUR at the
  time it moved, via keyless Binance klines (historical daily close) + Frankfurter
  (ECB) FX, cached; stablecoins pinned to $1. Surfaced in report, expert statement,
  CLI and web.
- **Targeted watchlist** (`monitor/watchlist.py`, `ariadne watch`) — register a
  suspect address; movement is detected by address-polling (baseline tx count →
  growth) so it is never missed, with optional auto-trace. A watched address in any
  scanned transaction is also scored critical by the live monitor.
- **Automatic cross-case linking** — a trace flags any address that also appears in
  a prior, differently-seeded investigation (knowledge-base `cross_references`),
  connecting cases through shared infrastructure. Shown in report, expert, web.
- **First-class entities** (`core/entity.py`, `ariadne entity`) — resolve an actor's
  whole wallet set into one persistent entity (aggregate labels, cash-out profile,
  risk flags), recognised by later traces.
- **Analyst manual attribution** (`ariadne label`) — record investigator-supplied
  attribution (source=analyst, high confidence) into the versioned store; it flows
  into every future trace.
- **Graph interop** (`report/export.py`) — every report also exports GraphML +
  node/edge CSV for Maltego, Gephi and i2 Analyst's Notebook.
- **Trace completeness metric** — the tracer now tracks followed-vs-pruned outflow;
  the report states what fraction of the money it actually followed and where it
  truncated at the depth horizon — honest uncertainty rather than false confidence.

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
