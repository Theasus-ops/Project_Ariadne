<p align="center">
  <img src="assets/banner.svg" alt="Ariadne — follow the thread of money out of the labyrinth" width="720">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-4b8bbe" alt="python">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-e9c46a" alt="license"></a>
  <img src="https://img.shields.io/badge/tests-28%20passing-4cc38a" alt="tests">
  <img src="https://img.shields.io/badge/chains-BTC · ETH · USDT · Tron-6cc4c9" alt="chains">
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
  Bitcoin, Ethereum, USDT/USDC, and USDT-on-Tron.
- **Grade findings by confidence** of an illicit link (Confirmed → High → Medium → Low → Info),
  deliberately conservatively — an exchange that received dirty funds is a *cash-out lead to
  subpoena*, **never** branded an offender.
- **Conservation-correct taint** — input-share apportionment plus an on-chain-received haircut,
  so "dirty value reaching a cash-out" never exceeds what the source disbursed.
- **Counter-laundering** — CoinJoin detection (Whirlpool / Wasabi), mixer / DEX / bridge
  break-points, and peel-chain + off-ramp detection.
- **Entity clustering** — common-input-ownership with exchange / CoinJoin guardrails: find
  every wallet a single actor controls, without absorbing half the chain.
- **Live monitoring** of new blocks and the mempool, with a transparent, explainable suspicion
  scorer that flags and auto-investigates — every point carries a human-readable reason.
- **24/7 daemon** (`--daemon`) — run continuously, alerting the operator via console, a persistent
  alert log, and an optional webhook (Slack / Discord / SIEM), with de-duplication and state that
  survives restarts.
- **Batch operations** (`ariadne operation`) — feed a list of suspect wallets; it investigates each,
  writes a per-wallet report, and connects them into a *ring* by the cash-out infrastructure they share.
- **~20,000 attribution labels** pulled from public feeds (OFAC sanctions, ransomware,
  scam / phishing, and named exchanges) via `ariadne update-intel`.
- **Persistent, tamper-evident knowledge base** — Ariadne remembers every investigation
  (hash-chained for evidence integrity) and recognises addresses it has seen before.
- **Reports** — a plain-English narrative plus JSON, Graphviz DOT, and an interactive HTML graph.
- **A themed web console** and a full CLI.

## Install

```bash
git clone <your-repo-url> && cd ariadne
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .              # installs the `ariadne` command
ariadne update-intel          # pull ~20k attribution labels (recommended)
```

## Usage

```bash
# Launch the web console  ->  http://127.0.0.1:8000
ariadne serve

# Trace a Bitcoin address (with taint, findings, and reports)
ariadne trace 12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw --chain btc --depth 4 --report

# Trace USDT-on-Tron — where investment-scam money actually moves
ariadne trace <T...address> --chain trx --depth 3

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

# What does Ariadne already know? Is the knowledge base intact?
ariadne recall <address>
ariadne knowledge

# Measure Ariadne's own accuracy — confusion matrix / FP-FN rates
ariadne validate
ariadne measure
```

## Supported chains

| Chain | Status |
|---|---|
| Bitcoin | ✅ full (keyless Blockstream) |
| Ethereum / USDT / USDC | ✅ full (keyless Blockscout) |
| USDT on Tron | ✅ full (keyless TronScan) |
| Litecoin / Dogecoin | ⚠️ requires a Blockchair API key |
| Monero | ❌ privacy coin — not address-traceable by design (offered only for honesty) |

## Architecture

```
ariadne/
  models.py            data model + multi-asset support + address validation
  cache.py             SQLite provenance cache (URL + timestamp + SHA-256 of raw bytes)
  knowledge.py         tamper-evident, hash-chained persistent knowledge base
  providers/           one per chain (Blockstream, Blockscout, TronScan, Blockchair, Monero)
  core/
    trace.py           multi-hop forward/backward tracer (input-share apportionment)
    taint.py           proportional haircut taint
    coinjoin.py        Whirlpool / Wasabi CoinJoin detection
    cluster.py         common-input-ownership entity clustering
    patterns.py        off-ramp + peel-chain detectors
    confidence.py      per-finding confidence-of-illicit-link grading
  enrich/
    labels.py          attribution label store
    feeds.py           public intelligence feeds (OFAC / ransomware / scam / exchanges)
    ofac.py            OFAC SDN importer
  monitor/             live block + mempool scoring and auto-investigation
  report/report.py     narrative + JSON + Graphviz + interactive HTML
  validation.py        known-answer accuracy harness
  web/                 Flask API + themed single-page console
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

- Attribution is ~20k labels vs. the **millions** a vendor maintains — many real cash-outs will
  still read as "unlabelled high-activity address."
- Validated only on a **tiny corpus** (`ariadne validate`) — not accredited or independently tested.
- **No** deep mixer de-anonymisation (Tornado correlation) or cross-chain bridge tracing yet.
- **Not** a deployable government system: the remaining gap is data-at-scale, formal validation,
  and institutional trust — not code.

## Testing

```bash
pip install -e ".[dev]"
pytest -q          # 28 deterministic tests (no network)
```

## Roadmap

- [ ] Grow the validation corpus (adversarial cases, measured false-positive / false-negative rates)
- [ ] Deeper attribution — more exchange coverage across chains
- [ ] Tornado deposit/withdrawal correlation, Uniswap cross-asset pass-through, bridge tracing
- [ ] Long-running monitoring daemon (dedup, alert delivery)

## License

[MIT](LICENSE). Use it lawfully.
