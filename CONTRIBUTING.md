# Contributing to Ariadne

Thanks for your interest. Ariadne is forensic software, so the bar is a little
different from a typical project: **a wrong number is worse than a missing
feature.** Contributions are welcome when they hold that line.

## Principles

1. **No hollow surface.** Every capability must be backed by real data. A chain,
   feed, or heuristic that cannot be verified against reality does not ship —
   gate it (see the disabled LTC/DOGE/XMR chains) rather than fake it.
2. **Honesty over polish.** State limitations plainly. If a technique is a
   *lead generator* (e.g. mixer de-anonymisation, ~35% recall), say so; do not
   dress a probability up as proof.
3. **Determinism.** The test suite runs fully offline. New logic must be testable
   without the network — inject the provider/data, don't call out to a live chain.
4. **Reproducibility.** Anything that feeds the evidence bundle or replay digest
   must be deterministic; put non-reproducible enrichments outside the digest.

## Development setup

```bash
git clone https://github.com/Theasus-ops/Project_Ariadne.git
cd Project_Ariadne
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,pdf]"
```

## Before you open a PR

```bash
ruff check ariadne/ tests/          # lint (E, F, I, B)
pytest -q                           # 100+ deterministic offline tests, all green
pytest --cov=ariadne --cov-report=term-missing   # keep new code covered
```

- Add tests for new behaviour and for the bug you're fixing (a regression test is
  the proof it's fixed).
- Match the surrounding style: type hints on public functions, docstrings that
  explain *why*, integer money in the smallest unit.
- Keep commits focused; describe the *what* and *why* in the message.

## Adding a data source

Public, keyless, and reputable sources only. Verify it live before wiring it in
(a token-contract *search* once returned a scam look-alike — trust canonical
issuer addresses, not search results). Record its licence/attribution in
[`NOTICE`](NOTICE).

## Reporting bugs and vulnerabilities

- Functional bugs → open a GitHub issue with a reproduction.
- Security vulnerabilities → **do not** open a public issue; follow
  [`SECURITY.md`](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the project's
[MIT Licence](LICENSE).
