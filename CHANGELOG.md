# Changelog

All notable changes to Ariadne are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [1.3.0] — 2026-07-14

Validation & measured error rates — toward the currency of accreditation. Not more
capability; **honest, reproducible numbers with the uncertainty attached**, because
a point estimate like "0% false positives" is not a credible claim without a
confidence interval and a sample size.

### Added
- **Wilson confidence intervals** (`ariadne/stats.py`) — the correct interval for a
  binomial proportion at the extremes (0% / 100%) and for small samples. Every
  reported rate now comes with a 95% CI and its n.
- **Cited ground-truth corpus** (`ariadne/corpus.py`) — individually-sourced
  landmark cases (hardcoded WannaCry wallets, an OFAC-listed address, a darklisted
  scam address, a clean control) plus documented **provenance** for the feed-sourced
  statistical corpus (OFAC SDN, ethereum-lists, ScamSniffer, Ransomwhere,
  etherscan-labels). Nothing fabricated; every classification is traceable.
- **`ariadne validate-report`** — a reproducible, offline, optionally Ed25519-signed
  report of measured error rates with intervals: operational safety (false-positive
  rate on legitimate controls), behavioural detection (adversarial constructed
  scenarios), and the honest ceiling (bare-address recall). Representative output:
  `FP 0.0% (95% CI 0.0–8.8%, n=40)`, `detection 100% (95% CI 56.6–100%, n=5)`,
  `bare-address recall 0.0% (95% CI 0.0–6.0%, n=60)` — the wide intervals honestly
  show where the corpus is still small.
- **`VALIDATION.md`** — the published methodology: what is measured, against what
  ground truth, how to reproduce it, and where it is weak.

### Changed
- False-positive controls now pool **multiple legitimate categories** (exchange /
  DEX / bridge / service), a broader specificity claim than exchanges alone.

### Tests
- **152 → 166** (Wilson interval against known values + invariants; corpus provenance;
  report structure, determinism, and intervals).

## [1.2.0] — 2026-07-14

Address-poisoning & dusting detection — a new detection dimension for one of the
highest-loss attacks of the current era (a single 2024 incident drained ~$68M). It
works on **every** supported chain from data Ariadne already holds — no new source.

### Added
- **Poisoning-detection engine** (`core/poisoning.py`):
  - `looks_alike` / `match_strength` — find addresses that share the truncated
    `0x1234…5678` display an attacker grinds a vanity look-alike to exploit;
  - `detect_address_poisoning` — pairs a genuine counterparty with a look-alike
    impersonator and grades it: **medium** (confusable pair), **high** (dust/zero-value
    primed look-alike of a real counterparty), **critical** (the victim actually sent
    real value to the look-alike — the poison worked). Orientation keys on *priming*,
    not amounts, because a successful poison is paid more than the genuine address;
  - `detect_dusting` — flags many distinct sources spraying dust at one address
    (a de-anonymisation campaign).
- **`ariadne poison-check <address>`** — analyses an address's counterparties for
  look-alike impersonation and dusting, on any chain.
- **Automatic trace guardrail** — `build_report` now flags confusable look-alike
  pairs in the graph (`lookalike_warnings`); `ariadne trace` prints a warning, and a
  new **`address_poisoning`** risk typology folds it into the composite grade and the
  expert report. The web console gets it via the same report path.

### Notes
- The look-alike flag is a **deterministic** function of the node set, so it is inside
  `build_report` and **replay reproduces it** (no evidence-digest divergence).
- Detection is an investigative lead, not proof: a look-alike pair warrants verifying
  full addresses, not an accusation.
- Tests **139 → 152**.

## [1.1.1] — 2026-07-14

Integration hardening — close the gaps a self-audit found after v1.1 shipped the
UTXO taint engine. No new capability; make the one just added reach everywhere it
should.

### Fixed
- **Replay now reproduces UTXO-model traces.** The offline replay re-derived the
  trace without retaining transactions, so re-running a `utxo-*` model produced
  all-zero taint and the report digest never matched — a sealed output-level trace
  would have failed its own reproducibility check. Replay now enables transaction
  collection for `utxo-*` models and respects the recorded traversal (`follow`).
- **The web console can use the UTXO models.** `/api/trace` previously forced any
  non-`haircut/poison/fifo` model back to haircut, so the v1.1 capability was
  unreachable from the UI. The endpoint now accepts `utxo-*`, enables transaction
  collection, and gracefully downgrades to the address-level equivalent on account
  chains or backward traces. The model selector exposes the three UTXO variants.

### Changed
- `UTXO_CHAINS` is now defined once in `ariadne.models` and shared by the CLI, the
  web API and replay (was a CLI-local constant).
- `requirements.txt` carries the same upper-bound caps as `pyproject.toml`.

### Tests
- **133 → 139:** the collection flag is load-bearing (utxo taint is zero without
  it — the replay root cause), plus the web taint-model resolver (enable on BTC
  forward, downgrade on account/backward, default on unknown).

## [1.1.0] — 2026-07-14

Reference-grade **UTXO / output-level taint** — the biggest rigor upgrade to the
crown jewel. The address-level models treat a wallet as one averaged pool; real
Bitcoin forensics tracks the fate of **individual transaction outputs**. This adds
that.

### Added
- **Output-level taint engine** (`core/utxo_taint.py`) with three models selectable
  on Bitcoin traces via `--taint-model`:
  - `utxo-poison` — any output of a transaction with a dirty input is fully dirty;
  - `utxo-haircut` — each output is dirty in proportion to the transaction's dirty
    input share (`dirty_in / total_in`), the fee absorbing its share — conservation-preserving;
  - `utxo-fifo` — *Clayton's Case* at output granularity: inputs consumed in
    transaction order, outputs paid in index order from the front of the dirty/clean
    queue, so the dirty parcel lands in **specific** outputs rather than being smeared
    across the address average.
- The tracer can **retain the transactions** it walks (`Tracer(collect_transactions=
  True)`, stored on `TraceResult.transactions`); the CLI enables this automatically for
  a `utxo-*` model. The retained set is not serialised into the report, so the evidence
  digest is unaffected.
- Because a UTXO is always created before it is spent, the output graph is a **DAG**;
  processing in `(time, txid)` order is a valid topological order, so the cyclic-
  undercount that affects single-pass address-level propagation over round-trips does
  **not** arise here.

### Notes
- Output-level models apply to **UTXO chains (Bitcoin; Litecoin/Dogecoin when
  enabled)** and to **forward** traces; the CLI rejects them cleanly on account-based
  chains (ETH/EVM/Tron), which have no UTXOs and correctly keep the balance-level
  haircut. The address-level `poison` / `haircut` / `fifo` defaults are unchanged and
  bit-for-bit reproducible.
- Tests **125 → 133**: the three models against hand-computed answers, the FIFO-vs-
  haircut divergence, multi-hop DAG propagation via prevout linkage, out-of-order
  processing, and the end-to-end path through the tracer.

## [1.0.0] — 2026-07-14

**First stable release.** No new investigative surface — this release closes the
gap between "impressive prototype" and "software you can actually deploy, operate,
and depend on." The engine was already sound; 1.0 makes it *operable*.

### Added — operability
- **Structured logging** (`ariadne.logging_setup`): levelled, timestamped
  diagnostics to **stderr** (so stdout stays clean for piping), an optional file
  sink, and `--log-json` for log pipelines. Global flags `--log-level`,
  `--log-file`, `--log-json`. The monitor daemon and autopilot now log heartbeats
  and every previously-silent failure instead of swallowing it.
- **CLI as a deployable command**: `ariadne --version`; a top-level error handler
  that never dumps a raw traceback at an operator; and proper **exit codes** — `0`
  success, `2` bad input, `1` unexpected failure (full traceback only with
  `--debug`), `130` on Ctrl-C — so cron / systemd / CI can react.
- **Production web server**: `ariadne serve` runs on **waitress** when installed
  (`pip install ariadne-tracer[serve]`) and falls back to Flask's dev server with a
  clear warning — no more accidentally exposing a dev server.
- **Resilient daemon**: a transient chain/network error no longer kills the 24/7
  monitor; it logs, backs off (capped exponential), and continues.

### Added — packaging & distribution
- **Typed distribution** (`py.typed`, PEP 561) so downstream type-checkers see
  Ariadne's hints; `Typing :: Typed` and full trove classifiers.
- **Single source of version truth** (`dynamic = ["version"]` from
  `ariadne.__version__`); dependency **upper bounds** pinned to the next major so a
  future breaking release can't silently break an install; `[serve]` extra;
  project URLs.
- **Hardened container**: runs as a **non-root** user, ships a `HEALTHCHECK`
  against `/api/health`, and installs a real (non-editable) build with `[pdf,serve]`.

### Added — governance
- `SECURITY.md` (private vulnerability reporting + operational hardening),
  `CONTRIBUTING.md`, `USE_POLICY.md` (lawful/responsible-use statement), `NOTICE`
  (attribution and licences for every data source: OSM/ODbL, OFAC, etherscan-labels,
  ScamSniffer, Ransomwhere, Binance, ECB/Frankfurter, …), and `CITATION.cff`.

### Changed
- `ariadne trace` now **raises** on an invalid address instead of printing and
  returning `0`, so automation sees a nonzero exit.
- CI: adds Python **3.13**, runs tests with coverage, builds+`twine check`s the
  sdist/wheel and smoke-tests the installed CLI, and builds the Docker image.

### Tests
- **113 → 125.** New suites cover the logging config (idempotency, levels, file
  sink), the CLI error contract (`--version`, exit codes, clean unexpected-error
  handling, Ctrl-C), and the production-WSGI selection with dev-server fallback.

## [0.9.0] — 2026-07-13

Verification and hardening — no new surface, a more trustworthy core. A tool that
asks to be believed in court has to earn it under a reviewer's own microscope, so
this release turns that microscope on Ariadne itself.

### Fixed
- **Batch operation silently dropped valid wallets** — `operation.read_wallets`
  documented `#` comments but only stripped *whole-line* ones. A trailing comment
  (`<address>  # note`) was mis-parsed, so the comment marker became the "chain
  code", the address then failed validation, and the wallet was quietly skipped
  from the investigation. Comments are now stripped from the first `#` on any line
  (addresses never contain `#`), so a commented input is always investigated.

### Added — test coverage where it was missing
- **`operation.py` and `validation.py`: 0% → 100%.** Both ship live CLI commands
  (`ariadne operation`, `ariadne validate`) yet had no tests. New deterministic,
  offline suites cover file parsing, chain inference, ring correlation by shared
  infrastructure, campaign rendering, the known-answer predicates, and the full
  trace → taint → report → check path through a fake provider.
- **Regression locks on load-bearing logic** (`tests/test_hardening.py`): the
  attribution tag-classifier (`feeds.classify_tags`) — including the priority rule
  that a sanctioned/illicit tag always beats a benign exchange tag; OFAC SDN XML
  parsing (`ofac.parse_sdn`) extracting only crypto-address identifiers; the alert
  fan-out (`notify`) staying best-effort when a sink fails; and Tron TRC-20
  parsing / pagination / success-filtering.
- Test count **87 → 113**; coverage of the previously-untested modules lifted
  (ofac 29→92%, notify 38→75%, tron 20→57%). Coverage artifacts are git-ignored.

## [0.8.0] — 2026-07-13

Probabilistic mixer de-anonymisation — the last research-grade frontier, built
rigorously and honestly.

### Added
- **CoinJoin linkability** (`core/demix.coinjoin_linkability`) — measures a mix's real
  anonymity set and finds any **deterministic** input→output links the amounts force
  (a value that can only balance one way), via a bounded subset-sum check. A perfect
  equal-denomination mix returns *no* links and states plainly that it is not
  reversible. Every detected CoinJoin now carries this analysis in its mix event.
- **Fixed-pool (Tornado-style) correlation** (`core/demix.MixerCorrelator`) — ranks
  candidate deposit↔withdrawal pairs using documented heuristics: address reuse
  (near-certain), same-cluster linkage, and temporal proximity weighted by the
  anonymity set. Probabilities are **capped** — timing alone never claims certainty.
- **`ariadne demix`** — runs both over a trace report; frames every result as a
  probabilistic lead (~35% real-world recall for this attack class), never proof.
- Imperfect-mix leaks now sharpen the `mixing_layering` risk typology.

## [0.7.0] — 2026-07-13

A smarter core, a real detection gap closed, and one-command deployability.

### Added
- **Taint-guided tracing** (`--follow dirty`) — an opt-in best-first forward
  traversal that follows the **dirty money**: it maintains one global priority
  frontier ranked by the dirty value each branch carries (online haircut) and spends
  a bounded node budget on the dirtiest paths first, resisting even-split and
  sub-threshold-peel evasion. The default breadth-first mode is unchanged.
- **Round-trip / wash-movement detection** (`core/patterns.detect_round_trips`) —
  flags value looping back to the seed or to a strictly-shallower (earlier) address,
  a recognised self-laundering / mule-recycling signal. Surfaced in the report
  patterns, the narrative, and a new `round_trip_laundering` risk typology.
- **Docker** — a `Dockerfile` (pure-Python, no system deps), `.dockerignore`, and a
  `Makefile` for one-command build/run/test. The web console or any CLI command runs
  in a container.

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
