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

## Accountability

Ariadne provides the tools to keep an investigation lawful and auditable — use them:

- Register the **legal basis** for each investigation (`ariadne authorize`) and run
  work under it (`trace --authorization <id> --actor <you>`), so every action is
  written to a **tamper-evident audit log** with a record of *who* did *what*,
  *when*, and *under what authority*.
- Verify the audit chain (`authority --audit-verify`) before relying on it — a
  broken chain means the record was altered and cannot be trusted.
- Apply **data minimisation**: review retention (`authority --oversight`) and keep
  data no longer than its lawful basis holds.
- Be prepared to produce the signed **oversight report** for whoever supervises your
  work. An investigation that ran without a valid authorization is flagged; that is a
  feature, not a nuisance.

## Jurisdiction

You are responsible for complying with the laws and data-protection regimes that
apply to you (e.g. GDPR in the EU), and with the terms of every data source
Ariadne queries (see [`NOTICE`](NOTICE)).

The software is provided "as is", without warranty, under the [MIT Licence](LICENSE).
