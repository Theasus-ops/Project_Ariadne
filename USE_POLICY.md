# Lawful & Responsible Use

Ariadne is built for **lawful financial-crime investigation** — by law
enforcement, financial-intelligence units, regulated compliance/AML teams,
accredited researchers, and investigators acting under proper legal authority.

Blockchain data is public, but *linking addresses to people* and *acting on those
links* is not consequence-free. Please use this tool accordingly.

## Intended uses

- Tracing the flow of funds in fraud, ransomware, sanctions-evasion, and
  laundering investigations.
- Compliance / AML screening and sanctions-exposure assessment.
- Academic and defensive security research.
- Producing documented, reproducible evidence for lawful proceedings.

## Out-of-bounds uses

Do **not** use Ariadne to:

- stalk, dox, harass, or surveil individuals without lawful authority;
- target people for their lawful political, journalistic, or activist activity;
- make adverse decisions about a person on an attribution alone.

## What the results are — and are not

- On-chain attribution is **probabilistic and provisional**. A label, a taint
  fraction, or a de-mixing lead is an *investigative lead*, not a verdict.
- "Clear" is not a clean bill of health — it means nothing was found within the
  traced horizon, which is not the same as nothing existing.
- Identifying an **operator** (e.g. an exchange or ATM operator) is not
  identifying a **person**. The customer, KYC record, and CCTV sit with that
  operator and are obtainable only under due legal process (subpoena, MLAT, court
  order). Ariadne deliberately stops at the operator and says so.
- Corroborate before you act, and preserve the signed evidence bundle so your
  work can be independently re-derived and challenged.

## Jurisdiction

You are responsible for complying with the laws and data-protection regimes that
apply to you (e.g. GDPR in the EU), and with the terms of every data source
Ariadne queries (see [`NOTICE`](NOTICE)).

The software is provided "as is", without warranty, under the [MIT Licence](LICENSE).
