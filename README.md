<p align="center">
  <img src="assets/banner.svg" alt="Ariadne — follow the thread of money out of the labyrinth" width="720">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-4b8bbe" alt="python">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-e9c46a" alt="license"></a>
  <img src="https://img.shields.io/badge/tests-75%20passing-4cc38a" alt="tests">
  <img src="https://img.shields.io/badge/chains-BTC · ETH · L2s · USDT · Tron-6cc4c9" alt="chains">
</p>

> **A blockchain money-flow tracer for lawful financial-crime investigation.**
> Give Ariadne an address tied to crime; it follows the money hop by hop, grades how
> confident it is that each stop is illicit, names the ones it can — and, crucially,
> **measures and reports its own accuracy.**

In the myth, Ariadne gave the thread that traced the path out of the Minotaur's labyrinth.
This tool follows the thread of money out of the blockchain maze.

---

## Why this one is different

Most forensic demos claim they work. Ariadne ships a harness that scores itself against
known-answer cases and prints exactly where it fails:

| Category | Score | Meaning |
|---|---|---|
| **Detection** | **4 / 4** | grades known ransomware / sanctioned / scam wallets correctly, and does **not** flag a clean wallet |
| **Attribution** | **1 / 2** | follows the money to the cash-out, but cannot yet *name* every exchange |

```bash
ariadne validate      # known-answer scorecard
ariadne measure       # confusion matrix: precision / recall / FP / FN
```

`measure` puts numbers on the trade-off: a **0% false-positive rate** — it never falsely accuses a
legitimate address — with recall bounded by attribution data. A tool honest about its own blind
spots, in both directions, is the entire point.

## What it does

- **Trace** value flow **forward** (where did it go?) or **backward** (source of funds) across
  **Bitcoin, Ethereum, Polygon, Arbitrum, Base, Optimism, and Tron** (native coins + USDT/USDC) —
  with **concurrent, rate-limit-aware fetching**. Investment-scam money lives on the L2s, so Ariadne
  follows it there.
- **Multi-seed investigations** (`ariadne investigate`) — trace *many* suspect addresses into **one
  combined graph**, then surface the **shared infrastructure** (addresses reached from ≥2 seeds), the
  **hubs** everything routes through, and the sub-rings — with a signed dossier + GraphML.
- **Statistical anomaly layer** — explainable behavioural-outlier detection (robust median/MAD
  z-scores) that complements the transparent rules: *"fan-out 5.2σ above peers — review"*, never a
  black box.
- **Autopilot** (`ariadne autopilot`) — an autonomous loop that polls the watchlist for movement and
  refreshes the intelligence feeds on a schedule, alerting via console / log / webhook.
- **Grade findings by confidence** of an illicit link (Confirmed → High → Medium → Low → Info),
  deliberately conservatively — an exchange that received dirty funds is a *cash-out lead to
  subpoena*, **never** branded an offender.
- **Selectable, documented taint models** — **poison** (maximal exposure), **haircut**
  (proportional dilution, the default), and **FIFO** (first-in-first-out / *Clayton's Case*, the
  rule courts actually use). Every result records *which model* produced it, so a finding is an
  auditable claim (`--taint-model fifo`), not a black-box score.
- **Signed evidence bundles** — every report can be sealed into an **Ed25519-signed** bundle with a
  per-investigation **chain of custody** (each conclusion tied to the exact API response it used,
  by URL + timestamp + SHA-256) and a **reproducibility manifest**. `ariadne verify-evidence`
  checks the signature and custody root with no key and no network.
- **Name the cash-out** — **exchange deposit-address discovery** attributes an unlabelled endpoint
  to the exchange it sweeps into (many funders → one hot wallet), and a **versioned attribution
  store** (provenance, confidence, supersession history) lets that coverage *compound* across
  investigations.
- **Graph link-analysis** over everything seen — shortest path between two entities, betweenness
  **centrality** (find the broker/hub), and **community detection** (find the ring).
- **Cross-chain / bridge correlation** — match a bridge deposit on one chain to the withdrawal on
  another by amount + time, to follow money through a chain hop (`ariadne correlate`).
- **Money-laundering typology + risk engine** — classifies the trace against recognised typologies
  (ransomware cash-out, sanctions exposure, mixing/peel layering, cross-chain layering) and folds
  them into a single, *explainable* composite risk grade.
- **Sanctions / illicit-exposure screening** (`ariadne screen`) — a compliance-grade verdict
  (sanctioned entity / direct / indirect / high-risk / clear) with hop-distance and exposed value.
- **Crypto-ATM geolocation** (`ariadne atm`) — a worldwide registry of physical crypto ATMs
  (operator + street address + coordinates) synced from OpenStreetMap. When a cash-out lands at an
  ATM operator, the report lists that operator's candidate kiosks; as an OSINT tool it also answers
  "which crypto ATMs are near this place?". On-chain data names the *operator* — the exact machine,
  the customer, and session video come from the operator under lawful process.
- **Temporal / behavioural fingerprinting** (`ariadne timeline`) — infers likely operator timezone
  from activity hours, plus movement velocity, burstiness and dormancy — labelled as the
  probabilistic lead it is, never a locate.
- **Entity clustering** by *two* pillars — common-input-ownership **and** change-address
  identification — with exchange / CoinJoin guardrails.
- **Court-ready expert report** — every `--report` also emits a standardized Markdown expert
  statement (methodology → findings → risk → chain of custody → **limitations** → next steps).
- **Fiat valuation** — every amount is priced in **USD/EUR at the time it moved** (keyless Binance
  klines + ECB/Frankfurter FX), so a report reads "≈ $1.2M (€1.1M)", not just "17.7 BTC".
- **Targeted watchlist** (`ariadne watch`) — register a suspect address; Ariadne alerts the instant
  it moves (address-polling, so it never misses it) and can auto-trace on movement.
- **Automatic cross-case linking** — when a trace touches an address seen in a *prior, separately-
  seeded* investigation, it flags the link — connecting cases through shared infrastructure.
- **First-class entities** (`ariadne entity`) — resolve an actor's whole wallet set into one
  persistent entity (aggregate labels, cash-out profile, risk), recognised by later traces.
- **Analyst attribution** (`ariadne label`) — record what the investigator has learned; it flows
  into every future trace.
- **Graph interop** — every report also exports **GraphML + node/edge CSV** for Maltego, Gephi, i2.
- **Trace completeness** — the report states what fraction of the money it actually followed vs.
  pruned, and where it truncated — honest uncertainty, not false confidence.
- **Counter-laundering** — CoinJoin detection (Whirlpool / Wasabi), mixer / DEX / bridge
  break-points, and peel-chain + off-ramp detection.
- **Live monitoring** of new blocks and the mempool, with a transparent, explainable suspicion
  scorer that flags and auto-investigates — every point carries a human-readable reason.
- **24/7 daemon** (`--daemon`) — run continuously, alerting the operator via console, a persistent
  alert log, and an optional webhook (Slack / Discord / SIEM), with de-duplication and state that
  survives restarts.
- **Batch operations** (`ariadne operation`) — feed a list of suspect wallets; it investigates each,
  writes a per-wallet report, and connects them into a *ring* by the cash-out infrastructure they share.
- **~28,000 attribution labels** pulled from public keyless feeds via `ariadne update-intel` —
  OFAC sanctions, ransomware, scam / phishing (ethereum-lists + ScamSniffer), and the full
  ~30k-address etherscan-labels set classified across the whole tag space (named exchanges, thousands
  of DEX/DeFi services, bridges, gambling, mixers, and stablecoin-issuer freezes) — the data that
  lets a trace *name* a cash-out.
- **Opsec by design** — route all provider queries through a **SOCKS/Tor proxy**, or point each
  chain at your **own self-hosted indexer**, so you never leak your investigative targets to a
  third-party explorer. Chains without real data are **gated off by default** (no hollow surface).
- **Persistent, tamper-evident knowledge base** — Ariadne remembers every investigation
  (hash-chained for evidence integrity) and recognises addresses it has seen before.
- **Two accuracy harnesses** — `ariadne validate` (known-answer real cases) and `ariadne
  adversarial` (a **deterministic, per-technique** detection scorecard: 100% detection, 0% false
  alarm on the constructed suite — fully reproducible offline).
- **Reports** — a plain-English narrative plus JSON, Graphviz DOT, and an interactive HTML graph.
- **A themed web console** with **real token-bound RBAC** (roles resolved server-side, not from a
  spoofable header) and audit logging; and a full CLI.

## Install

```bash
git clone https://github.com/Theseus-ops/Project_Ariadne.git && cd Project_Ariadne
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .              # installs the `ariadne` command
ariadne update-intel          # pull ~28k attribution labels (recommended)
ariadne atm-sync              # pull the worldwide crypto-ATM registry (optional)
```

## Usage

```bash
# Launch the web console  ->  http://127.0.0.1:8000
ariadne serve

# Trace a Bitcoin address (with taint, findings, signed evidence bundle, and reports)
ariadne trace 12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw --chain btc --depth 4 --report

# Pick a documented taint model and name the cash-outs it reaches
ariadne trace <address> --taint-model fifo --discover-deposits --report

# Verify a sealed evidence bundle (signature + chain of custody), offline
ariadne verify-evidence reports/<basename>.evidence.json

# Trace USDT on the chains scam money actually uses (Tron + the L2s)
ariadne trace <T...address> --chain trx --depth 3
ariadne trace 0x… --chain usdt-pol           # USDT on Polygon
ariadne trace 0x… --chain usdc-arb           # USDC on Arbitrum  (also: usdc-base, usdt-op, …)

# Trace MANY suspects into one graph; find the shared cash-outs and hubs
ariadne investigate --name theseus --seeds suspects.txt

# Run autonomously: alert on watchlist movement + keep feeds fresh
ariadne autopilot --auto-trace --webhook https://hooks.slack.com/...

# Backward: where did the money come from?
ariadne trace <address> --direction backward

# Find every wallet controlled by the same actor
ariadne cluster <address>

# Batch-investigate a list of wallets and connect them into a ring ("operation")
ariadne operation --name theseus --wallets suspects.txt

# Live-monitor new blocks or the mempool; auto-investigate the suspicious
ariadne monitor --chain btc --auto-trace
ariadne monitor --chain btc --mempool --auto-trace

# Run 24/7: watch continuously and alert the operator (console + log + webhook)
ariadne monitor --chain btc --daemon --auto-trace --webhook https://hooks.slack.com/...

# Compliance-grade sanctions / illicit-exposure screening
ariadne screen <address> --chain usdt

# Temporal / behavioural profile — active hours, likely timezone, velocity
ariadne timeline <address> --chain btc

# Crypto-ATM geolocation: sync the worldwide registry, then query it
ariadne atm-sync                                  # pull physical ATMs from OpenStreetMap
ariadne atm --near 37.9838,23.7275 --radius 8     # crypto ATMs within 8 km of a point
ariadne atm --operator "Bitcoin Depot"            # every kiosk of an operator (with coordinates)

# Watch a suspect address; alert (and auto-trace) the moment it moves
ariadne watch add <address> --chain btc --note "ring lead"
ariadne watch scan --auto-trace

# Resolve the actor behind an address into a persistent entity
ariadne entity <address> --chain btc

# Record what you've learned; it flows into every future trace
ariadne label <address> --category service --name "Courier wallet" --chain btc

# Name an unlabelled cash-out via exchange deposit-address discovery
ariadne attribute <address> --chain usdt

# Link analysis over everything traced so far: hubs, rings, and paths
ariadne graph                                   # central entities + candidate rings
ariadne graph --path <addrA> <addrB>            # money path between two entities

# Follow money through a chain hop (feed two single-chain trace reports)
ariadne correlate reports/trx_*.json reports/eth_*.json

# What does Ariadne already know? Is the knowledge base intact?
ariadne recall <address>
ariadne knowledge
ariadne intel-db --address <address>            # versioned attribution history

# Measure Ariadne's own accuracy
ariadne validate       # known-answer real cases
ariadne adversarial    # deterministic per-technique detection scorecard (offline)
ariadne measure        # confusion matrix / FP-FN rates

# Deployment: opsec + self-hosting
ariadne config                                              # show enabled chains, proxy, endpoints
ARIADNE_PROXY=socks5h://127.0.0.1:9050 ariadne trace <addr> # route queries through Tor
ARIADNE_ENDPOINT_BTC=http://my-esplora/api ariadne trace <addr>  # use your own indexer
```

## Supported chains

| Chain | Codes | Status |
|---|---|---|
| Bitcoin | `btc` | ✅ full (keyless Blockstream / self-hostable esplora) |
| Ethereum | `eth` `usdt` `usdc` | ✅ full (keyless Blockscout) |
| Polygon | `pol` `usdt-pol` `usdc-pol` | ✅ full (keyless Blockscout) |
| Arbitrum | `arb` `usdt-arb` `usdc-arb` | ✅ full (keyless Blockscout) |
| Base | `base` `usdc-base` | ✅ full (keyless Blockscout) |
| Optimism | `op` `usdt-op` `usdc-op` | ✅ full (keyless Blockscout) |
| Tron (USDT) | `trx` | ✅ full (keyless TronScan) |
| Litecoin / Dogecoin | `ltc` `doge` | ⛔ **gated off by default** — needs a Blockchair API key (`BLOCKCHAIR_API_KEY`) |
| Monero | `xmr` | ⛔ **gated off by default** — privacy coin, not address-traceable by design |

Every EVM endpoint and stablecoin contract above was verified live before inclusion (correct,
active address — never a look-alike scam token). BSC is intentionally absent: it has no stable
keyless Etherscan-compatible endpoint.

Gated chains are disabled rather than silently returning nothing — offering a chain that produces
no data is worse than not offering it. Enable explicitly (`ARIADNE_ENABLE_CHAINS=ltc,doge`) once you
have provisioned the data.

## Architecture

```
ariadne/
  models.py            data model + multi-asset support + address validation
  config.py            opsec: proxy + self-hosted endpoints + honest chain gating
  cache.py             thread-safe SQLite provenance cache (URL + timestamp + SHA-256)
  evidence.py          Ed25519 signing + chain of custody + reproducibility manifest
  knowledge.py         tamper-evident, hash-chained persistent knowledge base
  adversarial.py       deterministic per-technique detection scorecard
  providers/           one per chain (Blockstream, Blockscout, TronScan, Blockchair, Monero)
  core/
    trace.py           concurrent multi-hop forward/backward tracer (input-share apportionment)
    taint.py           entry point → taint_models
    taint_models.py    poison / haircut / FIFO, selectable & documented
    deposit.py         exchange deposit-address discovery (names cash-outs)
    graph.py           link analysis: shortest path, betweenness, community detection
    correlate.py       cross-chain / bridge deposit↔withdrawal correlation
    coinjoin.py        Whirlpool / Wasabi CoinJoin detection
    cluster.py         entity clustering (common-input + change-address pillars)
    change.py          change-address identification heuristics
    patterns.py        off-ramp + peel-chain detectors
    risk.py            money-laundering typology + composite risk engine
    screening.py       sanctions / illicit-exposure screening (compliance verdict)
    temporal.py        behavioural fingerprinting: active hours, timezone, velocity
    confidence.py      per-finding confidence-of-illicit-link grading
    entity.py          resolve a cluster into a persistent first-class entity
    investigation.py   multi-seed combined-graph analysis (shared infra, hubs, dossier)
    anomaly.py         explainable statistical outlier detection (robust z-scores)
  providers/           per chain; evm.py registry covers ETH + Polygon/Arbitrum/Base/Optimism
  enrich/
    labels.py          attribution label store
    attribution.py     versioned attribution store (provenance / confidence / history)
    feeds.py           public feeds + full-tag-space classifier (~28k labels)
    atm.py             worldwide crypto-ATM registry (OpenStreetMap) + geolocation
    prices.py          fiat valuation (Binance klines + ECB FX), historical + current
    ofac.py            OFAC SDN importer
  monitor/             live scoring, 24/7 daemon, watchlist alerts, autonomous autopilot
  report/report.py     narrative + JSON + Graphviz + interactive HTML
  report/expert.py     court-ready Markdown expert report
  report/export.py     GraphML + CSV export (Maltego / Gephi / i2)
  validation.py        known-answer accuracy harness
  web/                 Flask API + themed single-page console (token-bound RBAC)
  cli.py               command-line interface
```

## Legal & ethical scope

Ariadne reads **only public blockchain data** — the ledger is public by design. It does not
surveil individuals, touch private data, or attempt to deanonymise beyond public on-chain
heuristics. It is built for **lawful** financial-crime investigation, research, and education.
The web API binds to `127.0.0.1` and is unauthenticated by default — keep it local, or put it
behind your own auth and a trusted network.

## What it is *not* (honest limitations)

Ariadne is a real, working, and deliberately honest tool. It is **not** a substitute for a
commercial platform, and it says so:

- Attribution is ~28k feed labels vs. the **millions** a vendor maintains, and the etherscan-labels
  set is Ethereum-only — so **Bitcoin** cash-out naming stays weak. Deposit-address discovery and the
  versioned attribution store grow coverage from your own analysis, but many cash-outs will still
  read as "unlabelled high-activity address."
- The deterministic `adversarial` suite is exhaustive *by construction*; the real-world `validate`
  corpus is still **small** — neither is a formal accreditation or independent test.
- Bridge correlation is **statistical** (amount + time), never cryptographic proof; deep mixer
  de-anonymisation (Tornado) is still out of scope.
- **Not** a deployable government system on its own: the remaining gap is data-at-scale, formal
  accreditation, and institutional trust — not the engine.

## Testing

```bash
pip install -e ".[dev]"
pytest -q          # 75 deterministic tests (no network)
ruff check ariadne/ tests/
```

## Roadmap

Shipped:

- [x] Selectable, documented taint models (poison / haircut / FIFO)
- [x] Ed25519-signed evidence bundles with chain of custody + reproducibility
- [x] Exchange deposit-address discovery + versioned attribution store
- [x] Graph link-analysis (centrality / community detection / paths)
- [x] Cross-chain / bridge correlation (amount + time)
- [x] Concurrent tracing, opsec proxy / self-hosted endpoints, honest chain gating
- [x] Adversarial per-technique detection suite
- [x] Money-laundering typology + risk engine, sanctions-exposure screening
- [x] Temporal / behavioural fingerprinting; change-address clustering; court-ready expert report
- [x] Attribution at scale (~28k labels, full etherscan-labels tag space)
- [x] Crypto-ATM geolocation (OpenStreetMap registry + cash-out kiosk locations)
- [x] Fiat valuation (USD/EUR at time of movement)
- [x] Targeted watchlist, automatic cross-case linking, first-class entities, analyst attribution
- [x] Graph interop (GraphML / CSV), trace-completeness metric
- [x] Multi-chain: Polygon, Arbitrum, Base, Optimism (native + USDT/USDC)
- [x] Multi-seed combined-graph investigations with shared-infrastructure detection
- [x] Explainable statistical anomaly layer (robust z-scores)
- [x] Autonomous autopilot (watchlist movement + scheduled feed refresh)

Next:

- [ ] Deep mixer de-anonymisation (Tornado deposit/withdrawal correlation) — research-grade only
- [ ] Grow the real-world validation corpus toward measured, published error rates
- [ ] Bitcoin exchange-address coverage (the etherscan feed is Ethereum-only)
- [ ] Solana + a keyed BSC provider for fuller scam-chain coverage

## License

[MIT](LICENSE). Use it lawfully.
