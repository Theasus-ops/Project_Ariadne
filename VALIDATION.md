# Validation & measured error rates

This document is the honest accuracy account for Ariadne. It states what has been
measured, how, against what ground truth, and — deliberately — where the numbers
are weak. Every figure is **reproducible offline** and carries a **95% confidence
interval and a sample size**, because a point estimate like "0% false positives"
is not a credible claim without them.

Reproduce everything here with:

```bash
ariadne validate-report                 # measured error rates, with intervals
ariadne validate-report --report --sign # + a signed JSON/Markdown artifact
ariadne validate                        # the cited landmark cases (live)
ariadne adversarial                     # constructed-scenario detection (offline)
```

## What is measured

Three questions, because they have different answers and different strengths.

### 1. Operational safety — does it falsely accuse? (strong claim)

On a pool of **legitimate infrastructure** control addresses (exchanges, DEXes,
bridges, generic services), we grade each the way Ariadne grades a finding and count
how many are flagged illicit. This is the **false-positive rate**.

This is the defensible claim. In the shipped label set the observed false-positive
rate is **0%**, but we report it as *0% with a 95% Wilson interval* (e.g.
`0.0% (95% CI 0.0–8.8%, n=40)`) — because a clean run on a few dozen controls does
**not** prove a true zero, and pretending it does would be dishonest.

### 2. Behavioural detection — can it catch a laundering pattern? (real, but bounded)

The `adversarial` suite constructs laundering scenarios (peel chains, even splits,
sub-threshold peels, round-trips, a clean control) where the ground truth is known
**by construction**, and measures the detection rate. This measures analytical power
**independent of any label**.

Detection on these scenarios is high, but the suite is small, so the interval is
wide (e.g. `100% (95% CI 56.6–100%, n=5)`). The wide interval is the point: it tells
you honestly that the constructed corpus is not yet large enough to claim a tight
number.

### 3. The honest ceiling — recall on a bare address (low, by design)

We remove the positives' **own labels** and try to detect them from an address alone.
A bare address carries no behavioural signal, so recall here is ~0%
(`0.0% (95% CI 0.0–6.0%, n=60)`). This is reported plainly because it is the whole
truth of the tool: **accuracy is bounded by attribution DATA, not code.** No amount
of engineering turns a bare address into a detection without either a label or a
transaction graph to analyse.

## Ground truth & provenance

Nothing is fabricated. Classifications come from authoritative public sources where
membership is the ground truth by definition:

| Source | Provides | Basis |
|---|---|---|
| US Treasury OFAC SDN | sanctioned addresses | sanctioned as a matter of US law |
| ethereum-lists darklist | scam / phishing | community darklist membership |
| ScamSniffer blacklist | scam / phishing | curated blacklist membership |
| Ransomwhere | ransomware payments | crowdsourced, reviewed (CC0) |
| etherscan-labels | named services (legitimate controls) | public Etherscan labels |

In addition, a handful of **cited landmark cases** (see `ariadne/corpus.py`) are
individually hand-verifiable — the hardcoded WannaCry wallets, an OFAC-listed
address, a darklisted scam address, and a well-known clean control — so a reviewer
can check the anchor by hand.

## Methodology notes

- **Wilson score interval** for every proportion (`ariadne/stats.py`): correct at the
  extremes (0% / 100%) and for small samples, unlike the naive normal approximation.
- **Label-assisted vs behavioural** are reported separately; the label-assisted recall
  is near-100% *by construction* and is **not** presented as analytical power.
- The measurement is **deterministic** given the label set, so figures reproduce
  exactly. The optional signed artifact (`--sign`) makes the accuracy claim itself
  accountable.

## Honest limitations

- The corpus is **small** relative to what an accredited evaluation requires; the
  wide intervals say so. Growing it — especially the constructed-scenario and
  clean-control sets — is the priority, and the intervals will tighten as it grows.
- Ground truth inherits any error in the upstream public feeds.
- These are **internal** measurements, not an independent or formal accreditation.
  They are designed to be *reproducible by an outside party*, which is the necessary
  precondition for one — not a substitute for it.
