"""Command-line interface for Ariadne."""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import config
from .cache import ProvenanceCache
from .cases import CaseStore, InvestigationCase
from .core import temporal as temporal_mod
from .core.cluster import Clusterer
from .core.confidence import assess as assess_confidence
from .core.deposit import DepositDetector
from .core.patterns import detect_offramps, detect_peel_chains
from .core.taint import compute_taint
from .core.taint_models import METHODOLOGY
from .core.trace import Tracer
from .enrich import feeds, ofac
from .enrich.atm import ATMRegistry, atm_intel_for_report
from .enrich.attribution import AttributionStore
from .enrich.labels import (
    LabelStore,
    default_labels_path,
    intel_labels_path,
    ofac_labels_path,
    write_labels,
)
from .enrich.prices import PriceOracle, enrich_prices
from .knowledge import KnowledgeStore
from .models import NodeType, is_valid_address
from .monitor.monitor import Monitor
from .providers.bitcoin import BlockstreamProvider
from .providers.blockchair import BlockchairProvider
from .providers.evm import EVM_CHAINS, build_evm_provider, is_evm
from .providers.monero import MoneroProvider
from .providers.tron import TronProvider
from .report import report as report_mod

# All selectable chain codes: Bitcoin, Tron, the gated coins, and every EVM chain/asset.
_CHAINS = ["btc", "trx", *EVM_CHAINS.keys(), "ltc", "doge", "xmr"]


def short(addr: str) -> str:
    return addr if len(addr) <= 16 else f"{addr[:8]}..{addr[-6:]}"


def build_provider(chain: str, cache: ProvenanceCache, offline: bool = False):
    chain = chain.lower()
    config.require_enabled(chain)  # honest gating: refuse chains without real data
    if is_evm(chain):
        return build_evm_provider(chain, cache=cache, proxies=config.proxy(),
                                  base_url=config.endpoint(chain), offline=offline)
    kw = config.provider_kwargs(chain)
    if chain == "btc":
        return BlockstreamProvider(cache=cache, offline=offline, **kw)
    if chain in ("ltc", "doge"):
        return BlockchairProvider(chain=chain, cache=cache, **kw)
    if chain == "xmr":
        return MoneroProvider(cache=cache)
    if chain in ("trx", "tron"):
        return TronProvider(cache=cache, offline=offline, **kw)
    raise ValueError(f"Unsupported chain: {chain}")


def render(result, console: Console) -> None:
    asset = result.asset
    sym = asset.symbol
    console.rule(f"[bold]Ariadne - {result.direction} {sym} trace from {result.seed}")
    console.print(Panel(report_mod.narrative(result), title="Summary", border_style="cyan", padding=(1, 2)))
    findings = [n for n in result.nodes.values() if report_mod.is_flagged(n)]
    console.print(
        f"Addresses reached: [bold]{len(result.nodes)}[/]    "
        f"Value flows: [bold]{len(result.edges)}[/]    "
        f"Findings: [bold red]{len(findings)}[/]"
    )

    if findings:
        seed_node = result.nodes.get(result.seed)
        seed_category = seed_node.label_category if seed_node else ""
        conf_style = {"confirmed": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
        t = Table(title="Findings — graded by confidence of illicit link")
        t.add_column("Address")
        t.add_column("Label / type")
        t.add_column("Confidence")
        t.add_column(f"Dirty {sym}", justify="right")
        t.add_column("Taint", justify="right")
        for n in sorted(findings, key=lambda n: assess_confidence(n, seed_category).score, reverse=True):
            a = assess_confidence(n, seed_category)
            label = n.label_name or n.node_type.value
            t.add_row(
                short(n.address),
                label,
                f"[{conf_style[a.level]}]{a.level.upper()}[/]",
                asset.format(n.dirty_received),
                f"{int(n.taint_fraction * 100)}%",
            )
        console.print(t)

    t2 = Table(title=f"Value flows (top 20 by amount, {sym})")
    t2.add_column("From")
    t2.add_column("To")
    t2.add_column(sym, justify="right")
    t2.add_column("Txs", justify="right")
    for e in sorted(result.edges.values(), key=lambda e: e.value, reverse=True)[:20]:
        dst = result.nodes.get(e.dst)
        tag = ""
        if dst and dst.label_name:
            tag = f" [red]<{dst.label_name}>[/]"
        elif dst and dst.node_type == NodeType.SERVICE:
            tag = " [yellow](service)[/]"
        t2.add_row(short(e.src), short(e.dst) + tag, asset.format(e.value), str(len(e.txids)))
    console.print(t2)

    if result.mixing_events:
        tm = Table(title="Mixing break-points (CoinJoin entries)")
        tm.add_column("Address")
        tm.add_column("Kind")
        tm.add_column("Anon set", justify="right")
        tm.add_column("Denom", justify="right")
        for m in result.mixing_events:
            tm.add_row(short(m["address"]), m["kind"], str(m["anonymity_set"]), f"{m['denomination_btc']:.8f}")
        console.print(tm)

    offramps = detect_offramps(result)
    if offramps:
        to = Table(title=f"Off-ramps (value reaching exchanges / services, {sym})")
        to.add_column("From")
        to.add_column("To (service)")
        to.add_column(sym, justify="right")
        for r in offramps[:15]:
            to.add_row(short(r["from"]), short(r["to"]) + f" [{r['service']}]", f"{r['amount']:.8f}")
        console.print(to)

    peels = detect_peel_chains(result)
    if peels:
        console.print("[bold]Peel chains detected:[/]")
        for chain in peels[:5]:
            console.print("  " + " -> ".join(short(a) for a in chain))


def cmd_trace(args, console: Console) -> None:
    if not is_valid_address(args.address, args.chain):
        console.print(f"[red]Invalid {args.chain} address:[/] {args.address}")
        return
    label_paths = [default_labels_path(), ofac_labels_path(), intel_labels_path()]
    label_paths += [Path(p) for p in (args.labels or [])]
    labels = LabelStore.load(*label_paths)
    # Fold in attributions Ariadne has derived on prior runs (e.g. discovered
    # exchange deposit addresses) so coverage compounds across investigations.
    attribution = AttributionStore()
    attribution.as_label_store(labels)
    console.print(f"[dim]Loaded {len(labels)} address labels.[/]")

    cache = ProvenanceCache()
    cache.mark()  # scope the chain-of-custody trail to this investigation
    provider = build_provider(args.chain, cache)

    knowledge = KnowledgeStore()
    seed_norm = provider.normalize(args.address)
    prior = knowledge.recall(seed_norm)
    if prior["known"]:
        ent = prior["entity"]
        roles = ", ".join(json.loads(ent["roles"] or "[]")) or "n/a"
        console.print(
            Panel(
                f"Ariadne has encountered [bold]{short(seed_norm)}[/] before: "
                f"{ent['times_seen']} prior investigation(s); best grade "
                f"[bold]{ent['best_confidence'].upper()}[/]; observed as: {roles}.",
                title="Prior knowledge",
                border_style="yellow",
            )
        )

    tracer = Tracer(
        provider,
        service_tx_threshold=args.service_threshold,
        max_txs_per_address=args.max_txs,
        label_store=labels,
        workers=args.workers,
    )
    min_value = int(args.min_amount * (10 ** provider.asset_info.decimals))
    with console.status(f"Tracing {args.address} on {provider.asset_info.symbol} ..."):
        if args.direction == "backward":
            result = tracer.trace_backward(
                args.address,
                depth=args.depth,
                min_value=min_value,
                max_branch=args.max_branch,
            )
        else:
            result = tracer.trace_forward(
                args.address,
                depth=args.depth,
                min_value=min_value,
                max_branch=args.max_branch,
                follow=args.follow,
            )
    compute_taint(result, model=args.taint_model)
    console.print(f"[dim]Taint model: {result.taint_model} — {METHODOLOGY.get(result.taint_model, '')}[/]")

    if args.discover_deposits:
        unnamed = [
            n for n in result.nodes.values()
            if n.node_type == NodeType.SERVICE and not n.label_name and n.address != seed_norm
        ]
        if unnamed:
            detector = DepositDetector(provider, label_store=labels)
            named = 0
            with console.status("Naming cash-outs via exchange deposit-address discovery ..."):
                for n in unnamed[:8]:
                    finding = detector.analyze(n.address)
                    if finding.is_deposit:
                        n.label_name = finding.attribution
                        n.label_category = finding.target_category or "exchange"
                        n.label_source = "ariadne-deposit-heuristic"
                        attribution.upsert(
                            n.address, n.label_category, finding.attribution,
                            source="ariadne-deposit-heuristic",
                            confidence=0.75 if finding.confidence == "high" else 0.6,
                            chain=args.chain, provenance=finding.reason,
                        )
                        named += 1
            if named:
                console.print(f"[green]Deposit-address discovery named {named} previously-unlabelled cash-out(s).[/]")

    render(result, console)

    tprofile = temporal_mod.from_trace(result)
    if tprofile.events:
        console.print(Panel(tprofile.summary(), title="Behavioural / temporal profile", border_style="magenta"))

    report = report_mod.build_report(result)
    report["trace"]["chain"] = args.chain  # chain code, so the trace can be replayed

    # Fiat valuation: value the money in USD/EUR at the time it moved.
    if not args.no_fiat:
        oracle = PriceOracle()
        try:
            enrich_prices(report, oracle)
        finally:
            oracle.close()
        val = report.get("valuation", {})
        if val.get("seed_disbursed_usd") or val.get("total_cashout_usd"):
            def _fiat(usd, eur):
                if usd is None:
                    return "n/a"
                s = f"${usd:,.0f}"
                return s + (f" / €{eur:,.0f}" if eur is not None else "")
            console.print(Panel(
                f"Value disbursed by seed: [bold]{_fiat(val.get('seed_disbursed_usd'), val.get('seed_disbursed_eur'))}[/]\n"
                f"Value reaching cash-outs: [bold]{_fiat(val.get('total_cashout_usd'), val.get('total_cashout_eur'))}[/]\n"
                f"[dim]{val.get('note', '')}[/]",
                title="Fiat valuation", border_style="green"))

    # Crypto-ATM geolocation: if the trace cashed out at an ATM operator, attach
    # the operator's candidate physical kiosks from the local OSM-backed registry.
    atm_registry = ATMRegistry()
    try:
        if atm_registry.stats()["machines"] > 0:
            atm_intel = atm_intel_for_report(report, atm_registry)
            if atm_intel:
                report["atm_intel"] = atm_intel
                for hit in atm_intel:
                    lines = [f"Cash-out via crypto ATM operator [bold]{hit['operator']}[/] "
                             f"({hit['machine_count']} known machine(s))."]
                    for m in hit["candidate_locations"][:5]:
                        where = ", ".join(x for x in (m.get("city"), m.get("country")) if x) or "location on file"
                        lines.append(f"  📍 {where} — {m['lat']:.5f},{m['lon']:.5f}  {m['osm_url']}")
                    lines.append(f"[dim]{hit['note']}[/]")
                    console.print(Panel("\n".join(lines), title="Crypto-ATM cash-out — physical locations", border_style="bold red"))
    finally:
        atm_registry.close()

    risk = report.get("risk", {})
    if risk:
        rstyle = {"critical": "bold red", "high": "red", "elevated": "yellow", "low": "cyan", "minimal": "dim"}
        lines = [f"Composite risk: [{rstyle.get(risk['level'], 'white')}]{risk['level'].upper()} ({risk['score']}/100)[/]"]
        if risk.get("primary_typology"):
            lines.append(f"Primary typology: [bold]{risk['primary_typology']}[/]")
        typ = risk.get("typologies", [])
        if typ:
            lines.append("Typologies: " + ", ".join(t["name"] for t in typ[:4]))
        console.print(Panel("\n".join(lines), title="Risk & typology", border_style="red"))

    anomalies = report.get("anomalies", [])
    if anomalies:
        lines = [f"[bold]{short(a['address'])}[/] — {a['reason']}" for a in anomalies[:5]]
        console.print(Panel("\n".join(lines), title="Statistical anomalies (review required)", border_style="magenta"))

    comp = report.get("completeness", {})
    if comp:
        console.print(f"[dim]Trace completeness: followed [bold]{comp['value_followed_pct']}%[/] of seen outflow "
                      f"({comp['grade']}); {comp['truncated_at_horizon']} node(s) truncated at the depth horizon "
                      f"— raise --depth to follow them.[/]")

    # Cross-case linking: does any address here also appear in a prior investigation?
    xrefs = knowledge.cross_references([n["address"] for n in report.get("nodes", [])], seed_norm)
    if xrefs:
        report["cross_references"] = xrefs
        lines = []
        for x in xrefs[:8]:
            others = ", ".join(f"#{l['investigation_id']} (seed {short(l['other_seed'])})" for l in x["links"][:3])
            lines.append(f"[bold]{short(x['address'])}[/] also seen in: {others}")
        console.print(Panel("\n".join(lines), title=f"⚠ Cross-case links — {len(xrefs)} shared address(es)", border_style="bold yellow"))

    inv_id = knowledge.record_trace(report, args.chain)
    console.print(f"[dim]Recorded as investigation #{inv_id} in the tamper-evident knowledge base.[/]")
    knowledge.close()
    attribution.close()

    if args.report:
        safe = args.address.lower().replace("0x", "")[:12]
        basename = f"{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        paths = report_mod.write_all(result, Path(args.outdir), basename, report=report)
        console.print()
        for kind, path in paths.items():
            console.print(f"[green]{kind.upper():>4}[/] report: {path}")

        from .report.export import write_exports
        exports = write_exports(result, Path(args.outdir), basename)
        console.print(f"[green]GRAPH[/] interop: {exports['graphml'].name} + node/edge CSVs "
                      f"(Maltego / Gephi / i2)")

        bundle = None
        if not args.no_sign:
            from . import evidence
            bundle = evidence.build_evidence_bundle(report, cache=cache)
            bundle_path = evidence.write_bundle(bundle, Path(args.outdir) / f"{basename}.evidence.json")
            console.print(
                f"[green]SIGN[/] evidence bundle: {bundle_path}\n"
                f"       [dim]Ed25519 signed · {bundle['custody_count']} source record(s) · "
                f"custody root {bundle['custody_root'][:16]}…\n"
                f"       public key {bundle['signature']['public_key'][:16]}…  "
                f"(verify with `ariadne verify-evidence {bundle_path}`)[/]"
            )

        from .report.expert import write_expert_report
        expert_path = write_expert_report(report, Path(args.outdir) / f"{basename}.expert.md",
                                          bundle=bundle, case_ref=args.case_ref)
        console.print(f"[green]DOC [/] expert report (court-ready Markdown): {expert_path}")

        from .report import pdf as pdf_mod
        if pdf_mod.available():
            pdf_path = pdf_mod.write_expert_pdf(report, Path(args.outdir) / f"{basename}.expert.pdf",
                                                bundle=bundle, case_ref=args.case_ref)
            console.print(f"[green]PDF [/] expert report (court-ready, paginated): {pdf_path}")
        else:
            console.print("[dim]Install fpdf2 (`pip install fpdf2`) for a paginated PDF expert report.[/]")

    cache.close()


def cmd_update_labels(args, console: Console) -> None:
    if not args.ofac:
        console.print("[yellow]Nothing to do. Pass --ofac to import OFAC SDN sanctioned addresses.[/]")
        return
    out = Path(args.out) if args.out else ofac_labels_path()
    with console.status("Downloading and parsing the OFAC SDN list ..."):
        labels = ofac.import_ofac()
    count = write_labels(labels, out, note="OFAC SDN digital currency addresses (sanctioned).")
    console.print(f"[green]Imported {count} OFAC-sanctioned crypto addresses -> {out}[/]")


def cmd_update_intel(args, console: Console) -> None:
    from collections import Counter

    with console.status("Pulling OFAC sanctions + scam intelligence feeds ..."):
        labels = feeds.fetch_all()
    if not labels:
        console.print("[red]No intelligence fetched (network / feeds unavailable).[/]")
        return
    out = intel_labels_path()
    count = write_labels(labels, out, note="Public intelligence feeds: OFAC sanctions + scam darklist.")
    console.print(f"[green]Imported {count} intelligence labels -> {out}[/]")
    for cat, n in Counter(lab.category.value for lab in labels).most_common():
        console.print(f"  {cat}: {n}")

    # Mirror into the versioned attribution store so provenance/history accrues.
    store = AttributionStore()
    n_attr = store.import_labels(labels, provenance="ariadne update-intel feed pull")
    store.close()
    console.print(f"[dim]Mirrored {n_attr} labels into the versioned attribution store (provenance + history).[/]")


_LEVEL_STYLE = {"low": "dim", "medium": "yellow", "high": "red", "critical": "bold red"}


def _render_scored(monitor, scored, title, console, auto_trace, max_investigations, top=10):
    scored.sort(key=lambda s: s.score.total, reverse=True)
    sus = monitor.suspicious(scored)
    console.rule(f"[bold]{title}[/] - {len(scored)} txs, [bold red]{len(sus)} flagged[/]")

    shown = [s for s in scored if s.score.total > 0][:top]
    if shown:
        table = Table()
        table.add_column("Txid")
        table.add_column("Score", justify="right")
        table.add_column("Level")
        table.add_column("Top reasons")
        for s in shown:
            reasons = "; ".join(r.split("] ", 1)[-1] for r in s.score.reasons[:2]) or "-"
            table.add_row(
                short(s.tx.txid),
                str(s.score.total),
                f"[{_LEVEL_STYLE[s.score.level]}]{s.score.level}[/]",
                reasons,
            )
        console.print(table)

    if auto_trace and sus:
        for s in sus[:max_investigations]:
            console.print(f"  [bold]investigating[/] {short(s.tx.txid)} (score {s.score.total}) ...")
            paths = monitor.investigate(s)
            if paths:
                console.print(f"    [green]report[/]: {paths['json']}")
    return sus


def _scan_block(monitor, height, console, auto_trace, max_investigations, top=10):
    _, scored = monitor.poll_block(height)
    sym = monitor.provider.asset_info.symbol
    return _render_scored(monitor, scored, f"{sym} block {height}", console, auto_trace, max_investigations, top)


def cmd_monitor(args, console: Console) -> None:
    label_paths = [default_labels_path(), ofac_labels_path(), intel_labels_path()]
    label_paths += [Path(p) for p in (args.labels or [])]
    labels = LabelStore.load(*label_paths)
    console.print(f"[dim]Loaded {len(labels)} address labels.[/]")

    cache = ProvenanceCache()
    provider = build_provider(args.chain, cache)
    monitor = Monitor(
        provider,
        labels,
        threshold=args.threshold,
        sample=args.sample,
        trace_depth=args.trace_depth,
        large_value_units=args.large_value,
    )

    try:
        if args.daemon:
            from .monitor.daemon import MonitorDaemon
            from .monitor.notify import CompositeNotifier, ConsoleNotifier, FileNotifier, WebhookNotifier

            alert_log = args.alert_log or "reports/alerts/alerts.jsonl"
            notifiers = [ConsoleNotifier(console), FileNotifier(alert_log)]
            if args.webhook:
                notifiers.append(WebhookNotifier(args.webhook))
            daemon = MonitorDaemon(
                monitor,
                CompositeNotifier(notifiers),
                poll_interval=args.poll_interval,
                auto_trace=args.auto_trace,
                max_investigations=args.max_investigations,
            )
            console.print(
                f"[bold]Ariadne daemon[/] — watching {provider.asset_info.symbol} every "
                f"{args.poll_interval}s (threshold {args.threshold}); alerts -> console + {alert_log}"
                + (" + webhook" if args.webhook else "")
                + (", auto-investigating" if args.auto_trace else "")
                + ".  Press Ctrl+C to stop."
            )
            try:
                daemon.run()
            except KeyboardInterrupt:
                console.print("\n[dim]Daemon stopped.[/]")
        elif args.mempool:
            sym = provider.asset_info.symbol
            sus = _render_scored(
                monitor,
                monitor.poll_mempool(),
                f"{sym} mempool (unconfirmed)",
                console,
                args.auto_trace,
                args.max_investigations,
            )
            if sus and not args.auto_trace:
                console.print("[dim]Run with --auto-trace to follow these and report.[/]")
        elif args.watch:
            last = (args.block - 1) if args.block else provider.latest_block_height() - 1
            console.print(
                f"[dim]Watching {provider.asset_info.symbol} for new blocks "
                f"(poll every {args.poll_interval}s, stopping after {args.watch_max})...[/]"
            )
            processed = 0
            while processed < args.watch_max:
                tip = provider.latest_block_height()
                if tip > last:
                    for h in range(last + 1, tip + 1):
                        _scan_block(monitor, h, console, args.auto_trace, args.max_investigations)
                        processed += 1
                        if processed >= args.watch_max:
                            break
                    last = tip
                else:
                    time.sleep(args.poll_interval)
        elif args.blocks:
            tip = args.block or provider.latest_block_height()
            for h in range(tip - args.blocks + 1, tip + 1):
                _scan_block(monitor, h, console, args.auto_trace, args.max_investigations)
        else:
            sus = _scan_block(
                monitor,
                args.block or provider.latest_block_height(),
                console,
                args.auto_trace,
                args.max_investigations,
            )
            if sus and not args.auto_trace:
                console.print("[dim]Run with --auto-trace to follow these and report.[/]")
    finally:
        cache.close()


def cmd_cluster(args, console: Console) -> None:
    if not is_valid_address(args.address, args.chain):
        console.print(f"[red]Invalid {args.chain} address:[/] {args.address}")
        return
    label_paths = [default_labels_path(), ofac_labels_path(), intel_labels_path()]
    label_paths += [Path(p) for p in (args.labels or [])]
    labels = LabelStore.load(*label_paths)
    console.print(f"[dim]Loaded {len(labels)} address labels.[/]")

    cache = ProvenanceCache()
    provider = build_provider(args.chain, cache)
    clusterer = Clusterer(
        provider, label_store=labels, max_addresses=args.max_addresses, max_txs_per_address=args.max_txs
    )
    seed = provider.normalize(args.address)
    with console.status(f"Clustering the entity behind {args.address} ..."):
        cluster = clusterer.cluster(args.address)

    console.rule(f"[bold]Entity cluster — {len(cluster.members)} wallet(s) controlled by one actor")
    console.print(
        f"Co-spend links: [bold]{len(cluster.links)}[/]    "
        f"Services this entity used: [bold]{len(cluster.services_touched)}[/]"
    )
    for addr in sorted(cluster.members)[:25]:
        lab = labels.get(addr)
        tag = f"  [cyan]{lab.category.value}: {lab.name}[/]" if lab else ""
        marker = "[red]►[/] " if addr == seed else "  "
        console.print(f"{marker}{addr}{tag}")
    if len(cluster.members) > 25:
        console.print(f"  ... and {len(cluster.members) - 25} more")
    if cluster.services_touched:
        console.print("\n[bold]Services this entity interacted with (cash-out leads):[/]")
        for addr, why in list(cluster.services_touched.items())[:10]:
            console.print(f"  {short(addr)} — {why}")

    if args.report:
        import json

        outdir = Path(args.outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        safe = args.address.lower().replace("0x", "")[:12]
        path = outdir / f"cluster_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path.write_text(json.dumps(cluster.as_dict(), indent=2), encoding="utf-8")
        console.print(f"\n[green]cluster report[/]: {path}")

    cache.close()


def cmd_case(args, console: Console) -> None:
    store = CaseStore(args.store)
    if args.action == "create":
        case = InvestigationCase(args.case_id or f"case-{int(time.time())}", args.title or "Untitled case")
        if args.note:
            case.add_note(args.note)
        if args.tag:
            for tag in args.tag:
                case.add_tag(tag)
        saved = store.save_case(case)
        console.print(f"[green]Created case[/] {saved['case_id']}")
    elif args.action == "list":
        for case in store.list_cases():
            console.print(f"- {case['case_id']}: {case['title']} ({case['investigator']})")
    elif args.action == "export":
        path = store.export_bundle(args.case_id, args.outdir)
        console.print(f"[green]Exported evidence bundle[/] {path}")
    elif args.action in {"add-note", "add-evidence"}:
        case_data = store.load_case(args.case_id)
        if case_data is None:
            console.print(f"[red]Case not found[/] {args.case_id}")
            return
        case = InvestigationCase(case_data["case_id"], case_data["title"], case_data.get("investigator", "operator"))
        case.notes = list(case_data.get("notes", []))
        case.evidence = list(case_data.get("evidence", []))
        case.tags = list(case_data.get("tags", []))
        case.timeline = list(case_data.get("timeline", []))
        case.created_at = case_data.get("created_at", case.created_at)
        case.updated_at = case_data.get("updated_at", case.updated_at)
        if args.action == "add-note" and args.note:
            case.add_note(args.note)
        elif args.action == "add-evidence":
            detail = getattr(args, "detail", None) or "CLI evidence entry"
            case.add_evidence({"type": "manual", "detail": detail})
        saved = store.save_case(case)
        console.print(f"[green]Updated case[/] {saved['case_id']}")


def cmd_recall(args, console: Console) -> None:
    knowledge = KnowledgeStore()
    r = knowledge.recall(args.address)
    if not r["known"]:
        console.print(f"[dim]No prior knowledge of {args.address}.[/]")
        knowledge.close()
        return
    ent = r["entity"]
    console.rule(f"[bold]Prior knowledge — {args.address}")
    console.print(
        f"Seen [bold]{ent['times_seen']}[/] time(s)    Best grade: [bold]{ent['best_confidence'].upper()}[/]    "
        f"Roles: {', '.join(json.loads(ent['roles'] or '[]')) or 'n/a'}    "
        f"Labels: {', '.join(json.loads(ent['labels'] or '[]')) or 'none'}"
    )
    t = Table(title="Appearances in past investigations")
    t.add_column("Inv#")
    t.add_column("When")
    t.add_column("Seed of")
    t.add_column("Chain")
    t.add_column("Grade")
    for a in r["appearances"]:
        when = datetime.fromtimestamp(a["created_at"] / 1000).strftime("%Y-%m-%d %H:%M")
        t.add_row(str(a["investigation_id"]), when, short(a["seed"]), a["chain"], a["confidence"].upper())
    console.print(t)
    knowledge.close()


def cmd_knowledge(args, console: Console) -> None:
    knowledge = KnowledgeStore()
    s = knowledge.stats()
    integ = knowledge.verify_integrity()
    console.rule("[bold]Ariadne knowledge base")
    console.print(
        f"Investigations: [bold]{s['investigations']}[/]    Entities known: [bold]{s['entities']}[/]    "
        f"Observed flows: [bold]{s['edges']}[/]    Flagged entities: [bold red]{s['flagged_entities']}[/]"
    )
    status = "[green]VERIFIED[/]" if integ["ok"] else f"[red]BROKEN at #{integ['broken_at']}[/]"
    console.print(f"Tamper-evident integrity: {status}  ({integ['records']} records in the hash chain)")
    for r in knowledge.recent(10):
        when = datetime.fromtimestamp(r["created_at"] / 1000).strftime("%Y-%m-%d %H:%M")
        console.print(
            f"  #{r['id']:<3} {when}  {short(r['seed']):<18} {r['chain']:<5} {r['direction']:<8} "
            f"findings={r['findings']} top={r['top_confidence'].upper()}"
        )
    knowledge.close()


def cmd_validate(args, console: Console) -> None:
    from . import validation

    labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
    console.print(f"[dim]Loaded {len(labels)} labels (run `ariadne update-intel` first for full coverage).[/]")
    cache = ProvenanceCache()
    total = passed = 0
    by_cat: dict[str, list[int]] = {}
    for case in validation.CASES:
        console.rule(f"[bold]{case.name}")
        console.print(f"[dim]{case.ground_truth}[/]")
        try:
            results = validation.run_case(case, build_provider, labels, cache)
        except Exception as exc:  # network / provider failure -> report, don't crash
            console.print(f"[red]ERROR[/] {exc}")
            continue
        for desc, ok, cat in results:
            total += 1
            passed += int(ok)
            slot = by_cat.setdefault(cat, [0, 0])
            slot[0] += int(ok)
            slot[1] += 1
            console.print(f"  {'[green]PASS[/]' if ok else '[red]FAIL[/]'} [{cat}] {desc}")
    cache.close()

    console.rule("[bold]Scorecard")
    console.print(f"Overall: [bold]{passed}/{total}[/] checks passed")
    for cat, (p, t) in by_cat.items():
        console.print(f"  {cat}: [bold]{p}/{t}[/]")
    att = by_cat.get("attribution", [0, 0])
    if att[1] and att[0] < att[1]:
        console.print(
            "[yellow]Attribution gap:[/] Ariadne detects and grades known-bad wallets, but cannot "
            "yet NAME the cash-out exchanges — that needs exchange-address data it does not have."
        )


def cmd_adversarial(args, console: Console) -> None:
    from . import adversarial

    res = adversarial.run()
    console.rule("[bold]Adversarial detection suite — deterministic, per-technique")
    t = Table(title="Constructed laundering scenarios (ground truth by construction)")
    t.add_column("Scenario")
    t.add_column("Technique")
    t.add_column("Expected")
    t.add_column("Result")
    t.add_column("Pass")
    for r in res["results"]:
        t.add_row(
            r.scenario, r.technique,
            "present" if r.expected else "absent",
            r.detail,
            "[green]PASS[/]" if r.passed else "[red]FAIL[/]",
        )
    console.print(t)
    console.rule("[bold]Scorecard")
    console.print(
        f"Overall: [bold]{res['passed']}/{res['total']}[/] scenarios passed\n"
        f"Detection rate (techniques caught): [bold green]{res['detection_rate'] * 100:.0f}%[/]\n"
        f"False-alarm rate (on the clean control): [bold]{res['false_alarm_rate'] * 100:.0f}%[/]\n"
        "[dim]Fully reproducible offline — no network, no live-chain dependence.[/]"
    )


def cmd_benchmark(args, console: Console) -> None:
    from . import benchmark

    with console.status("Measuring accuracy per category over the labelled corpus ..."):
        res = benchmark.run(per_category=args.sample, negatives=args.negatives)
    m = res["overall"]["metrics"]
    console.rule(f"[bold]Accuracy benchmark — {res['sample']['positives']} illicit + "
                 f"{res['sample']['negatives']} legitimate addresses")
    console.print(f"Precision [bold]{m['precision'] * 100:.1f}%[/]   Recall [bold]{m['recall'] * 100:.1f}%[/]   "
                  f"FP-rate [bold]{m['false_positive_rate'] * 100:.1f}%[/]   "
                  f"Accuracy [bold]{m['accuracy'] * 100:.1f}%[/]   "
                  f"Behavioural recall [bold]{res['behavioural_recall'] * 100:.1f}%[/]")
    t = Table(title="Per-category recall")
    t.add_column("Category")
    t.add_column("Sample", justify="right")
    t.add_column("Detected", justify="right")
    t.add_column("Missed", justify="right")
    t.add_column("Recall", justify="right")
    for cat, d in res["per_category"].items():
        t.add_row(cat, str(d["n"]), str(d["detected"]), str(d["missed"]), f"{d['recall'] * 100:.1f}%")
    console.print(t)

    if args.report:
        outdir = Path(args.outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        payload = res
        if args.sign:
            from .evidence import Signer
            payload = {"result": res, "signature": Signer().sign_dict(res)}
        (outdir / f"benchmark_{stamp}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        (outdir / f"benchmark_{stamp}.md").write_text(benchmark.to_markdown(res), encoding="utf-8")
        console.print(f"\n[green]Accuracy report:[/] {outdir / f'benchmark_{stamp}.md'}"
                      + ("  [dim](JSON is Ed25519-signed)[/]" if args.sign else ""))


def cmd_measure(args, console: Console) -> None:
    from . import measurement

    with console.status("Measuring precision / recall against the labelled corpus ..."):
        res = measurement.run(per_category=args.sample, negatives=args.negatives)
    console.rule(
        f"[bold]FP/FN measurement — {res['positives']} illicit + {res['negatives']} legitimate addresses"
    )

    def show(name: str, block: dict, note: str) -> None:
        tp, fp, tn, fn = block["confusion"]
        m = block["metrics"]
        console.print(f"\n[bold]{name}[/]  [dim]{note}[/]")
        console.print(f"  confusion:  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
        console.print(
            f"  precision={m['precision'] * 100:.1f}%   recall={m['recall'] * 100:.1f}%   "
            f"FP-rate={m['false_positive_rate'] * 100:.1f}%   FN-rate={m['false_negative_rate'] * 100:.1f}%   "
            f"accuracy={m['accuracy'] * 100:.1f}%"
        )

    show("Label-assisted (operational)", res["label_assisted"], "how safe: does it falsely accuse a clean address?")
    show("Behavioural (by itself)", res["behavioural"], "real recall: can it detect a bad actor it has NO label for?")

    la = res["label_assisted"]["metrics"]
    be = res["behavioural"]["metrics"]
    console.rule("[bold]Verdict")
    console.print(
        f"False-positive rate: [green]{la['false_positive_rate'] * 100:.1f}%[/] — it does not falsely accuse.\n"
        f"Autonomous recall: [red]{be['recall'] * 100:.1f}%[/] — by itself it misses bad actors it has no label for.\n"
        "Accuracy is bounded by attribution DATA, not code — you cannot measure or code your way to it."
    )


def cmd_operation(args, console: Console) -> None:
    from . import operation

    wallets = operation.read_wallets(args.wallets)
    if not wallets:
        console.print("[red]No wallets found in the input file.[/]")
        return
    labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
    outdir = Path(args.outdir) / args.name
    outdir.mkdir(parents=True, exist_ok=True)
    console.rule(f"[bold]Operation {args.name} — investigating {len(wallets)} wallet(s)")

    cache = ProvenanceCache()
    knowledge = KnowledgeStore()
    results = []
    for i, (addr, chain) in enumerate(wallets, 1):
        if not chain or not is_valid_address(addr, chain):
            console.print(f"[dim]{i}/{len(wallets)}[/] [red]skip[/]  {short(addr)}  (invalid / unknown chain)")
            results.append(operation.WalletResult(addr, chain or "?", ok=False, error="invalid address or unknown chain"))
            continue
        try:
            provider = build_provider(chain, cache)
            tracer = Tracer(
                provider, label_store=labels,
                service_tx_threshold=args.service_threshold, max_txs_per_address=args.max_txs,
            )
            min_value = int(args.min_amount * (10 ** provider.asset_info.decimals))
            result = tracer.trace_forward(
                provider.normalize(addr), depth=args.depth, min_value=min_value, max_branch=args.max_branch
            )
            compute_taint(result)
            report = report_mod.build_report(result)
            knowledge.record_trace(report, chain)
            base = f"{chain}_{addr.lower().replace('0x', '')[:12]}"
            paths = report_mod.write_all(result, outdir, base)
            wr = operation.wallet_result_from_report(addr, chain, report, str(paths["json"]))
            results.append(wr)
            console.print(
                f"[dim]{i}/{len(wallets)}[/] {short(addr)} [{chain}] -> "
                f"[bold]{wr.risk_level.upper()}[/] ({wr.findings} findings)"
            )
        except Exception as exc:
            results.append(operation.WalletResult(addr, chain, ok=False, error=str(exc)))
            console.print(f"[dim]{i}/{len(wallets)}[/] [red]error[/] {short(addr)}: {exc}")
    knowledge.close()
    cache.close()

    campaign = operation.correlate(results)
    md_path = operation.write_campaign(args.name, results, campaign, outdir)

    shared = campaign["shared_infrastructure"]
    console.rule(f"[bold]Operation {args.name} — links found")
    if shared:
        table = Table(title="Shared infrastructure — wallets linked by a common endpoint")
        table.add_column("Endpoint")
        table.add_column("Type / label")
        table.add_column("Linked wallets", justify="right")
        for s in shared[:15]:
            table.add_row(short(s["endpoint"]), s["label"] or s["category"], str(len(s["wallets"])))
        console.print(table)
    else:
        console.print("[dim]No shared infrastructure across these wallets.[/]")
    console.print(f"\n[green]Per-wallet reports + operation summary:[/] {md_path}")


def cmd_attribute(args, console: Console) -> None:
    if not is_valid_address(args.address, args.chain):
        console.print(f"[red]Invalid {args.chain} address:[/] {args.address}")
        return
    labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
    attribution = AttributionStore()
    attribution.as_label_store(labels)
    cache = ProvenanceCache()
    provider = build_provider(args.chain, cache)

    existing = labels.get(provider.normalize(args.address))
    console.rule(f"[bold]Attribution — {args.address}")
    if existing:
        console.print(f"Already labelled: [bold]{existing.name}[/] ({existing.category.value}, source {existing.source})")

    detector = DepositDetector(provider, label_store=labels, max_txs=args.max_txs)
    with console.status("Analysing for an exchange deposit-address signature ..."):
        finding = detector.analyze(args.address)

    if finding.is_deposit:
        style = {"high": "bold green", "medium": "yellow"}.get(finding.confidence, "cyan")
        console.print(f"[{style}]DEPOSIT ADDRESS ({finding.confidence.upper()} confidence)[/] — {finding.attribution}")
        console.print(f"  {finding.reason}")
        console.print(f"  Sweeps to: {finding.sweep_target}   Funders: {finding.funders}   "
                      f"Forwarded: {finding.forwarded_fraction:.0%}")
        attribution.upsert(
            provider.normalize(args.address), finding.target_category or "exchange", finding.attribution,
            source="ariadne-deposit-heuristic",
            confidence=0.75 if finding.confidence == "high" else 0.6,
            chain=args.chain, provenance=finding.reason,
        )
        console.print("[dim]Written to the attribution store (coverage compounds across investigations).[/]")
    else:
        console.print(f"[dim]No exchange deposit-address signature: {finding.reason}[/]")
    attribution.close()
    cache.close()


def cmd_intel_db(args, console: Console) -> None:
    attribution = AttributionStore()
    if args.import_feeds:
        labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
        n = 0
        for addr, lab in labels._by_address.items():  # project loaded labels into the store
            attribution.upsert(addr, lab.category.value, lab.name, lab.source or "feed", chain="")
            n += 1
        console.print(f"[green]Imported {n} labels into the versioned attribution store.[/]")
    s = attribution.stats()
    console.rule("[bold]Attribution store")
    console.print(
        f"Live attributions: [bold]{s['live']}[/]    Distinct addresses: [bold]{s['addresses']}[/]    "
        f"Superseded (history): [bold]{s['superseded']}[/]"
    )
    for cat, n in sorted(s["by_category"].items(), key=lambda kv: kv[1], reverse=True):
        console.print(f"  {cat}: {n}")
    if args.address:
        console.print()
        hist = attribution.history(args.address)
        if hist:
            console.print(f"[bold]History for {args.address}:[/]")
            for h in hist:
                mark = "[dim](superseded)[/]" if h.superseded else "[green](current)[/]"
                console.print(f"  v{h.version} {mark} {h.category}/{h.name} — conf {h.confidence:.2f}, source {h.source}")
        else:
            console.print(f"[dim]No attribution history for {args.address}.[/]")
    attribution.close()


def cmd_correlate(args, console: Console) -> None:
    from .core import correlate as corr

    reports = []
    for path in args.reports:
        try:
            reports.append(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            console.print(f"[red]Could not read {path}:[/] {exc}")
    if len(reports) < 1:
        console.print("[red]Provide at least one trace report JSON (two+ chains for cross-chain).[/]")
        return

    matches = corr.correlate_reports(
        reports, amount_tolerance=args.tolerance, max_delay_seconds=args.max_delay
    )
    console.rule(f"[bold]Bridge correlation — {len(reports)} report(s)")
    if not matches:
        console.print("[dim]No bridge deposit↔withdrawal pairs matched by amount + time.[/]")
        return
    t = Table(title="Correlated bridge legs (probabilistic, not proof)")
    t.add_column("Deposit (chain/amount)")
    t.add_column("Withdrawal (chain/amount)")
    t.add_column("Δamount", justify="right")
    t.add_column("Δtime", justify="right")
    t.add_column("Confidence", justify="right")
    for m in matches[:args.top]:
        dt = f"{m.time_delta}s" if m.time_delta is not None else "—"
        t.add_row(
            f"{m.deposit.chain} {m.deposit.amount}",
            f"{m.withdrawal.chain} {m.withdrawal.amount}",
            f"{m.amount_delta:.4f}", dt, f"{m.confidence:.0%}",
        )
    console.print(t)
    console.print("[dim]Correlation is statistical (amount+time). Treat linked legs as a lead, not proof.[/]")


def cmd_entity(args, console: Console) -> None:
    from .core.entity import build_entity

    if not is_valid_address(args.address, args.chain):
        console.print(f"[red]Invalid {args.chain} address:[/] {args.address}")
        return
    labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
    AttributionStore().as_label_store(labels)

    knowledge = KnowledgeStore()
    prior = knowledge.find_entity(args.address)
    if prior is not None:
        console.print(f"[yellow]Known entity:[/] {short(args.address)} was already profiled as entity "
                      f"#{prior['id']} ({prior['member_count']} wallets). Re-resolving to refresh.")
    cache = ProvenanceCache()
    provider = build_provider(args.chain, cache)
    clusterer = Clusterer(provider, label_store=labels, max_addresses=args.max_addresses, max_txs_per_address=args.max_txs)
    with console.status(f"Resolving the entity behind {args.address} ..."):
        cluster = clusterer.cluster(args.address)
    entity = build_entity(cluster, labels)
    eid = knowledge.save_entity(entity)
    cache.close()

    console.rule(f"[bold]Entity #{eid} — {entity['member_count']} wallet(s), risk {entity['risk'].upper()}")
    if entity["risk_flags"]:
        console.print(f"[bold red]Risk flags:[/] {', '.join(entity['risk_flags'])}")
    if entity["category_counts"]:
        console.print("Attribution across the entity: " +
                      ", ".join(f"{c}×{n}" for c, n in sorted(entity["category_counts"].items(), key=lambda x: -x[1])))
    console.print(f"Cash-out infrastructure touched: [bold]{entity['cash_out_count']}[/]    "
                  f"Co-spend links: [bold]{entity['cospend_links']}[/]")
    for addr in entity["members"][:25]:
        lab = entity["labels"].get(addr)
        tag = f"  [cyan]{lab['category']}: {lab['name']}[/]" if lab else ""
        marker = "[red]►[/] " if addr == args.address else "  "
        console.print(f"{marker}{short(addr)}{tag}")
    if entity["member_count"] > 25:
        console.print(f"  … and {entity['member_count'] - 25} more")
    console.print(f"[dim]Persisted as entity #{eid}; a future trace touching any member will recognise it.[/]")
    knowledge.close()


def cmd_label(args, console: Console) -> None:
    """Analyst manual attribution — record what the investigator has learned."""
    valid_cats = {
        "sanctioned", "frozen", "ransomware", "darknet", "scam", "mixer", "bridge",
        "dex", "gambling", "atm", "exchange", "service", "other",
    }
    if args.category not in valid_cats:
        console.print(f"[red]Category must be one of:[/] {', '.join(sorted(valid_cats))}")
        return
    if not is_valid_address(args.address, args.chain):
        console.print(f"[red]Invalid {args.chain} address:[/] {args.address}")
        return
    store = AttributionStore()
    store.upsert(
        args.address, args.category, args.name or "", source="analyst",
        confidence=0.9, chain=args.chain, provenance=args.note or "analyst manual attribution",
    )
    store.close()
    console.print(f"[green]Recorded analyst attribution:[/] {short(args.address)} → "
                  f"{args.category}" + (f" ({args.name})" if args.name else "")
                  + " [dim](flows into future traces)[/]")


def cmd_watch(args, console: Console) -> None:
    from .monitor.watchlist import Watchlist

    wl = Watchlist()
    try:
        if args.action == "add":
            if not is_valid_address(args.address or "", args.chain):
                console.print(f"[red]Invalid {args.chain} address:[/] {args.address}")
                return
            wl.add(args.address, args.chain, note=args.note or "", priority=args.priority)
            console.print(f"[green]Watching[/] {short(args.address)} on {args.chain}"
                          + (f" — {args.note}" if args.note else ""))
        elif args.action == "remove":
            ok = wl.remove(args.address)
            console.print(f"[green]Removed[/] {short(args.address)}" if ok else f"[dim]Not on the watchlist:[/] {args.address}")
        elif args.action == "list":
            entries = wl.list()
            if not entries:
                console.print("[dim]Watchlist is empty. Add with `ariadne watch add <addr> --chain btc`.[/]")
                return
            t = Table(title=f"Watchlist ({len(entries)})")
            t.add_column("Address")
            t.add_column("Chain")
            t.add_column("Note")
            t.add_column("Baseline txs", justify="right")
            for e in entries:
                t.add_row(short(e["address"]), e["chain"], e["note"] or "-",
                          str(e["last_tx_count"]) if e["last_tx_count"] is not None else "—")
            console.print(t)
        elif args.action == "scan":
            cache = ProvenanceCache()
            with console.status("Polling watched addresses for movement ..."):
                alerts = wl.check_movements(build_provider, cache)
            if not alerts:
                console.print("[dim]No movement on watched addresses since the last scan.[/]")
            else:
                console.rule(f"[bold red]{len(alerts)} watched address(es) MOVED")
                for a in alerts:
                    console.print(f"  [bold red]►[/] {short(a['address'])} ({a['chain']}) — "
                                  f"{a['new_transactions']} new tx(s)" + (f"  [{a['note']}]" if a["note"] else ""))
                    if args.auto_trace:
                        labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
                        provider = build_provider(a["chain"], cache)
                        tracer = Tracer(provider, label_store=labels, workers=4)
                        mv = int(0.001 * (10 ** provider.asset_info.decimals))
                        res = tracer.trace_forward(provider.normalize(a["address"]), depth=3, min_value=mv, max_branch=4)
                        compute_taint(res)
                        base = f"watch_{a['chain']}_{a['address'][:12]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        paths = report_mod.write_all(res, Path("reports/alerts"), base)
                        console.print(f"    [green]report[/]: {paths['json']}")
            cache.close()
    finally:
        wl.close()


def cmd_atm_sync(args, console: Console) -> None:
    registry = ATMRegistry()
    bbox = None
    if args.bbox:
        try:
            bbox = tuple(float(x) for x in args.bbox.split(","))
            assert len(bbox) == 4
        except (ValueError, AssertionError):
            console.print("[red]--bbox must be 'south,west,north,east'[/]")
            registry.close()
            return
    scope = "worldwide" if bbox is None else f"bbox {args.bbox}"
    with console.status(f"Syncing crypto-ATM locations from OpenStreetMap ({scope}) ..."):
        try:
            n = registry.sync_from_osm(bbox=bbox, timeout=args.timeout)
        except Exception as exc:
            console.print(f"[red]OSM sync failed:[/] {exc}")
            registry.close()
            return
    s = registry.stats()
    console.print(f"[green]Synced {n} crypto ATMs.[/] Registry now holds "
                  f"[bold]{s['machines']}[/] machines from [bold]{s['operators']}[/] operators "
                  f"across [bold]{s['countries']}[/] countries.")
    registry.close()


def cmd_atm(args, console: Console) -> None:
    registry = ATMRegistry()
    s = registry.stats()
    if s["machines"] == 0:
        console.print("[yellow]ATM registry is empty — run `ariadne atm-sync` first.[/]")
        registry.close()
        return
    if args.operators:
        console.rule("[bold]Top crypto-ATM operators")
        for o in registry.operators(limit=args.limit):
            console.print(f"  {o['machines']:>5}  {o['operator']}")
    elif args.near:
        try:
            lat, lon = (float(x) for x in args.near.split(","))
        except ValueError:
            console.print("[red]--near must be 'lat,lon'[/]")
            registry.close()
            return
        results = registry.near(lat, lon, radius_km=args.radius, limit=args.limit)
        console.rule(f"[bold]Crypto ATMs within {args.radius} km of {lat},{lon}")
        for m in results:
            where = ", ".join(x for x in (m.get("street"), m.get("city"), m.get("country")) if x) or "—"
            console.print(f"  {m['distance_km']:>6.2f} km  [bold]{m['operator']}[/]  {where}  "
                          f"[dim]{m['lat']:.5f},{m['lon']:.5f}  {m['osm_url']}[/]")
        if not results:
            console.print("[dim]No crypto ATMs found in that radius.[/]")
    elif args.operator:
        machines = registry.by_operator(args.operator, limit=args.limit)
        console.rule(f"[bold]Crypto ATMs operated by '{args.operator}' ({len(machines)})")
        for m in machines:
            where = ", ".join(x for x in (m.get("street"), m.get("city"), m.get("country")) if x) or "—"
            console.print(f"  [bold]{m['operator']}[/]  {where}  [dim]{m['lat']:.5f},{m['lon']:.5f}  {m['osm_url']}[/]")
    else:
        console.rule("[bold]Crypto-ATM registry")
        console.print(f"Machines: [bold]{s['machines']}[/]    Operators: [bold]{s['operators']}[/]    "
                      f"Countries: [bold]{s['countries']}[/]")
        console.print("[dim]Query with --near lat,lon | --operator NAME | --operators[/]")
    registry.close()


def cmd_screen(args, console: Console) -> None:
    if not is_valid_address(args.address, args.chain):
        console.print(f"[red]Invalid {args.chain} address:[/] {args.address}")
        return
    labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
    AttributionStore().as_label_store(labels)
    cache = ProvenanceCache()
    provider = build_provider(args.chain, cache)
    tracer = Tracer(provider, label_store=labels, workers=args.workers)
    min_value = int(args.min_amount * (10 ** provider.asset_info.decimals))
    with console.status(f"Screening {args.address} for sanctions / illicit exposure ..."):
        result = tracer.trace_forward(args.address, depth=args.depth, min_value=min_value, max_branch=args.max_branch)
    compute_taint(result)
    report = report_mod.build_report(result)
    cache.close()

    scr = report["screening"]
    verdict_style = {
        "sanctioned_entity": "bold white on red", "direct_exposure": "bold red",
        "indirect_exposure": "red", "high_risk_exposure": "yellow", "clear": "green",
    }
    console.rule(f"[bold]Sanctions / illicit-exposure screening — {args.address}")
    console.print(f"Verdict: [{verdict_style.get(scr['verdict'], 'white')}] {scr['verdict'].upper().replace('_',' ')} [/]")
    for r in scr["reasons"]:
        console.print(f"  • {r}")
    if scr["nearest_hops"] is not None:
        console.print(f"Nearest illicit touchpoint: [bold]{scr['nearest_hops']}[/] hop(s)    "
                      f"Exposed traced value: [bold]{scr['exposed_value']}[/] {report['asset']}")
    for hit in (scr["direct_hits"] + scr["indirect_hits"])[:8]:
        name = hit.get("label") or hit.get("category")
        console.print(f"  [red]►[/] {short(hit['address'])} — {name} ({hit['category']}, {hit['hops']} hop)")
    console.print(f"[dim]{scr['note']}[/]")


def cmd_timeline(args, console: Console) -> None:
    if not is_valid_address(args.address, args.chain):
        console.print(f"[red]Invalid {args.chain} address:[/] {args.address}")
        return
    cache = ProvenanceCache()
    provider = build_provider(args.chain, cache)
    with console.status(f"Profiling temporal behaviour of {args.address} ..."):
        profile = temporal_mod.profile_address(provider, args.address, max_txs=args.max_txs)
    cache.close()

    console.rule(f"[bold]Temporal / behavioural profile — {args.address}")
    if not profile.events:
        console.print("[dim]No timestamped activity found.[/]")
        return
    console.print(profile.summary())
    from datetime import datetime as _dt
    if profile.first_seen and profile.last_seen:
        fs = _dt.utcfromtimestamp(profile.first_seen).strftime("%Y-%m-%d")
        ls = _dt.utcfromtimestamp(profile.last_seen).strftime("%Y-%m-%d")
        console.print(f"Active {fs} → {ls} ({profile.active_days} day span), {profile.events} movements.")
    # Compact hour-of-day sparkline (UTC).
    hist = profile.hour_histogram
    peak = max(hist) or 1
    bars = "▁▂▃▄▅▆▇█"
    spark = "".join(bars[min(len(bars) - 1, int((c / peak) * (len(bars) - 1)))] for c in hist)
    console.print(f"Hour-of-day (UTC 00→23): [cyan]{spark}[/]")
    if profile.likely_utc_offset is not None:
        sign = "+" if profile.likely_utc_offset >= 0 else ""
        console.print(f"Likely operator timezone: [bold]UTC{sign}{profile.likely_utc_offset}[/] — {profile.region_hint} "
                      "[dim](probabilistic lead, not proof)[/]")


def cmd_graph(args, console: Console) -> None:
    from .core.graph import MoneyGraph

    knowledge = KnowledgeStore()
    graph = MoneyGraph.from_knowledge(knowledge)
    knowledge.close()

    s = graph.summary()
    console.rule("[bold]Money-flow graph — link analysis over all investigations")
    console.print(
        f"Nodes: [bold]{s['nodes']}[/]    Edges: [bold]{s['edges']}[/]    "
        f"Components: [bold]{s['components']}[/]    Largest: [bold]{s['largest_component']}[/]"
    )
    if s["nodes"] == 0:
        console.print("[dim]The knowledge graph is empty — run some traces first.[/]")
        return

    if args.path:
        src, dst = args.path
        path = graph.shortest_path(src, dst, directed=not args.undirected)
        console.rule(f"[bold]Path {short(src)} → {short(dst)}")
        if path:
            console.print(" → ".join(short(a) for a in path) + f"   ([bold]{len(path) - 1}[/] hops)")
        else:
            console.print("[yellow]No path found in the observed flow graph.[/]")
        return

    hubs = graph.hubs(args.top)
    if hubs:
        t = Table(title="Central entities (hubs / brokers by betweenness)")
        t.add_column("Address")
        t.add_column("Label")
        t.add_column("Betweenness", justify="right")
        t.add_column("In", justify="right")
        t.add_column("Out", justify="right")
        for h in hubs:
            t.add_row(short(h["address"]), h["label"] or "-", f"{h['betweenness']:.2f}",
                      str(h["degree_in"]), str(h["degree_out"]))
        console.print(t)

    communities = graph.communities(min_size=args.min_community)
    if communities:
        console.print(f"\n[bold]Candidate rings (communities ≥ {args.min_community} members):[/]")
        for c in communities[:args.top]:
            labels = f"  [cyan]{', '.join(c['labels'])}[/]" if c["labels"] else ""
            console.print(
                f"  size [bold]{c['size']}[/], {c['internal_edges']} internal flows{labels}: "
                + ", ".join(short(m) for m in c["members"][:6])
                + (" …" if c["size"] > 6 else "")
            )


def cmd_replay(args, console: Console) -> None:
    """Independently re-derive a trace OFFLINE from the preserved cache and prove
    it matches the signed bundle — the gold standard of forensic reproducibility."""
    from . import evidence

    try:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]Could not read bundle:[/] {exc}")
        return
    report = bundle.get("report", {})
    trace = report.get("trace", {})
    chain, seed = trace.get("chain"), trace.get("seed")
    if not chain or not seed:
        console.print("[yellow]This bundle predates replay support[/] (no chain code recorded). "
                      "Re-generate it with a current `ariadne trace --report`.")
        return
    params = trace.get("parameters", {})
    model = trace.get("taint_model", "haircut")
    expected = bundle.get("manifest", {}).get("report_digest")

    labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
    AttributionStore().as_label_store(labels)

    console.rule(f"[bold]Replay — re-deriving {short(seed)} on {chain} from preserved cache")
    cache = ProvenanceCache()
    cache.mark()
    try:
        provider = build_provider(chain, cache, offline=True)  # cache only — no network
        tracer = Tracer(provider, label_store=labels,
                        service_tx_threshold=params.get("service_tx_threshold", 3000),
                        max_txs_per_address=params.get("max_txs_per_address", 200))
        minv = params.get("min_value_sats", 100_000)
        depth = params.get("depth", 2)
        branch = params.get("max_branch", 8)
        norm = provider.normalize(seed)
        if trace.get("direction") == "backward":
            res = tracer.trace_backward(norm, depth=depth, min_value=minv, max_branch=branch)
        else:
            res = tracer.trace_forward(norm, depth=depth, min_value=minv, max_branch=branch)
        compute_taint(res, model)
        new_report = report_mod.build_report(res)
        new_report["trace"]["chain"] = chain
        new_digest = evidence.report_digest(new_report)
        accessed = cache.provenance()
    finally:
        cache.close()

    # 1. Custody integrity: every source response re-read must match the sealed hash.
    custody = {c["key"]: c["sha256"] for c in bundle.get("custody", [])}
    used_in_custody = [r for r in accessed if r["key"] in custody]
    tampered = [r["key"] for r in used_in_custody if custody[r["key"]] != r["sha256"]]
    missing = [r["key"] for r in accessed if r["key"] not in custody]

    console.print(f"Source records re-read from cache: [bold]{len(accessed)}[/] "
                  f"({len(used_in_custody)} matched against the sealed custody list)")
    if tampered:
        console.print(f"[bold red]CACHE TAMPERED[/] — {len(tampered)} preserved response(s) no longer "
                      f"match their sealed SHA-256. The evidence store was altered.")
        return
    console.print("[green]✓ Custody intact[/] — every preserved source response matches its sealed SHA-256.")

    # 2. Reproducibility of the derived result.
    if new_digest == expected:
        console.print("[bold green]✓ FULLY REPRODUCED[/] — the identical report was re-derived offline "
                      "from the preserved data (digest matches the signed bundle).")
    else:
        note = ""
        if missing:
            note = (" Some data was not in the local cache — replay must run on the machine that holds "
                    "the original cache.")
        console.print("[yellow]Result differs[/] — the source data is intact, but the re-derived report "
                      "digest does not match." + note +
                      " The most common cause is that the attribution label set changed since sealing "
                      "(labels are interpretive, not on-chain).")
        console.print(f"[dim]expected {str(expected)[:20]}… got {new_digest[:20]}…[/]")


def cmd_verify_evidence(args, console: Console) -> None:
    from . import evidence

    try:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]Could not read bundle:[/] {exc}")
        return
    res = evidence.verify_bundle(bundle)
    console.rule(f"[bold]Evidence verification — {args.bundle}")
    manifest = bundle.get("manifest", {})
    console.print(
        f"Tool: {manifest.get('tool')} {manifest.get('tool_version')}    "
        f"Seed: {short(str(manifest.get('seed')))}    Chain: {manifest.get('chain')}    "
        f"Taint model: {manifest.get('taint_model')}"
    )
    console.print(
        f"Source records in custody: [bold]{res['custody_count']}[/]    "
        f"Signed by public key: [dim]{(res['public_key'] or '')[:24]}…[/]"
    )
    if res["ok"]:
        console.print("[bold green]VALID[/] — signature verifies, custody root intact, report unaltered.")
    else:
        console.print("[bold red]INVALID[/] — " + "; ".join(res["reasons"]))


def cmd_config(args, console: Console) -> None:
    d = config.describe()
    console.rule("[bold]Ariadne deployment configuration")
    console.print(f"Enabled chains: [bold green]{', '.join(d['enabled_chains'])}[/]")
    if d["gated_off"]:
        console.print(f"Gated off (no real data): [dim]{', '.join(d['gated_off'])}[/]")
    console.print(f"Query proxy (opsec): [bold]{d['proxy'] or 'none — queries go direct (leaks targets to explorers)'}[/]")
    if d["endpoints"]:
        console.print("Self-hosted endpoints:")
        for c, ep in d["endpoints"].items():
            console.print(f"  {c}: {ep}")
    else:
        console.print("Self-hosted endpoints: [dim]none (using public explorers)[/]")
    console.print(f"Blockchair API key: {'set' if d['blockchair_key_set'] else 'not set'}    "
                  f"Config file: {d['config_file']}")
    console.print(
        "\n[dim]Set ARIADNE_PROXY=socks5h://127.0.0.1:9050 to route queries through Tor, and "
        "ARIADNE_ENDPOINT_BTC=http://your-esplora/api to use your own indexer.[/]"
    )


def cmd_investigate(args, console: Console) -> None:
    from . import operation
    from .core import investigation as inv
    from .report.export import write_exports

    seeds = operation.read_wallets(args.seeds)
    if not seeds:
        console.print("[red]No seeds found in the input file.[/]")
        return
    labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
    AttributionStore().as_label_store(labels)

    outdir = Path(args.outdir) / args.name
    outdir.mkdir(parents=True, exist_ok=True)
    console.rule(f"[bold]Operation {args.name} — investigating {len(seeds)} seed(s) into one graph")

    cache = ProvenanceCache()
    knowledge = KnowledgeStore()
    results, seed_rows = [], []
    for i, (addr, chain) in enumerate(seeds, 1):
        if not chain or not is_valid_address(addr, chain):
            console.print(f"[dim]{i}/{len(seeds)}[/] [red]skip[/] {short(addr)} (invalid/unknown chain)")
            continue
        try:
            provider = build_provider(chain, cache)
            tracer = Tracer(provider, label_store=labels, workers=args.workers,
                            service_tx_threshold=args.service_threshold, max_txs_per_address=args.max_txs)
            mv = int(args.min_amount * (10 ** provider.asset_info.decimals))
            r = tracer.trace_forward(provider.normalize(addr), depth=args.depth, min_value=mv, max_branch=args.max_branch)
            compute_taint(r)
            results.append(r)
            report = report_mod.build_report(r)
            knowledge.record_trace(report, chain)
            brief = report.get("brief", {})
            seed_rows.append({"seed": provider.normalize(addr), "chain": chain,
                              "risk": brief.get("risk_level", "?"),
                              "findings": report.get("summary", {}).get("findings", 0),
                              "cash_outs": len([n for n in report["nodes"] if n["type"] == "service"])})
            console.print(f"[dim]{i}/{len(seeds)}[/] {short(addr)} [{chain}] -> {brief.get('risk_level', '?').upper()}")
        except Exception as exc:
            console.print(f"[dim]{i}/{len(seeds)}[/] [red]error[/] {short(addr)}: {exc}")
    knowledge.close()
    cache.close()

    if not results:
        console.print("[red]No seeds traced successfully.[/]")
        return

    analysis = inv.analyse(results, labels)
    merged = analysis["merged"]
    dossier = inv.build_dossier(args.name, seed_rows, analysis, asset=merged.asset.symbol)
    dossier_path = outdir / f"DOSSIER_{args.name}.md"
    dossier_path.write_text(dossier, encoding="utf-8")
    exports = write_exports(merged, outdir, f"operation_{args.name}")

    shared = analysis["shared_infrastructure"]
    console.rule(f"[bold]Operation {args.name} — combined-graph findings")
    console.print(f"Combined graph: [bold]{analysis['summary']['nodes']}[/] addresses, "
                  f"[bold]{analysis['summary']['edges']}[/] flows.")
    if shared:
        t = Table(title="Shared infrastructure — links binding the seeds into a ring")
        t.add_column("Address")
        t.add_column("Label / type")
        t.add_column("Seeds", justify="right")
        for x in shared[:15]:
            t.add_row(short(x["address"]), x["label"] or x["category"] or "unlabelled", str(x["seed_count"]))
        console.print(t)
    else:
        console.print("[dim]No shared infrastructure across the seeds.[/]")
    hubs = [h for h in analysis["hubs"] if h["betweenness"] > 0]
    if hubs:
        console.print("[bold]Top hub:[/] " + short(hubs[0]["address"]) +
                      (f" ({hubs[0]['label']})" if hubs[0].get("label") else "") +
                      f"  betweenness {hubs[0]['betweenness']}")
    console.print(f"\n[green]Dossier:[/] {dossier_path}")
    console.print(f"[green]Combined graph (GraphML for Maltego/Gephi/i2):[/] {exports['graphml']}")


def cmd_autopilot(args, console: Console) -> None:
    from .monitor.autopilot import Autopilot
    from .monitor.notify import CompositeNotifier, ConsoleNotifier, FileNotifier, WebhookNotifier
    from .monitor.watchlist import Watchlist

    wl = Watchlist()
    if not wl.list():
        console.print("[yellow]Watchlist is empty[/] — add targets with `ariadne watch add`. "
                      "Autopilot will still refresh intelligence feeds on schedule.")
    notifiers = [ConsoleNotifier(console), FileNotifier(args.alert_log or "reports/alerts/autopilot.jsonl")]
    if args.webhook:
        notifiers.append(WebhookNotifier(args.webhook))
    notifier = CompositeNotifier(notifiers)

    auto_trace = None
    if args.auto_trace:
        def auto_trace(mv, cache):
            labels = LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())
            provider = build_provider(mv["chain"], cache)
            tracer = Tracer(provider, label_store=labels, workers=4)
            minv = int(0.001 * (10 ** provider.asset_info.decimals))
            res = tracer.trace_forward(provider.normalize(mv["address"]), depth=3, min_value=minv, max_branch=4)
            compute_taint(res)
            base = f"autopilot_{mv['chain']}_{mv['address'][:12]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            return str(report_mod.write_all(res, Path("reports/alerts"), base)["json"])

    ap = Autopilot(wl, build_provider, notifier, ProvenanceCache,
                   watch_interval=args.watch_interval, feed_interval=args.feed_interval, auto_trace=auto_trace)

    if args.once:
        r = ap.cycle()
        console.print(f"[green]Autopilot cycle:[/] {r['watch_alerts']} watchlist alert(s); "
                      f"feeds {'refreshed' if r['feeds_refreshed'] else 'up to date'}.")
        return
    console.print(f"[bold]Ariadne autopilot[/] — polling the watchlist every {args.watch_interval}s, "
                  f"refreshing feeds every {args.feed_interval // 3600}h"
                  + (", auto-tracing movements" if args.auto_trace else "") + ".  Ctrl+C to stop.")
    try:
        ap.run()
    except KeyboardInterrupt:
        console.print("\n[dim]Autopilot stopped.[/]")


def cmd_serve(args, console: Console) -> None:
    from .web.app import create_app

    if args.host not in ("127.0.0.1", "localhost"):
        console.print(
            "[yellow]Warning:[/] binding to a non-loopback address exposes the UI to your network. "
            "The API has no authentication — only do this behind a trusted network or VPN."
        )
    auth_token = args.auth_token or None
    audit_log_path = Path(args.audit_log) if args.audit_log else None
    auth_tokens = None
    if args.auth_tokens:
        auth_tokens = {}
        for pair in args.auth_tokens.split(","):
            if ":" in pair:
                tok, role = pair.split(":", 1)
                auth_tokens[tok.strip()] = role.strip()
    app = create_app(auth_token=auth_token, audit_log_path=audit_log_path, auth_tokens=auth_tokens)
    if config.describe()["proxy"]:
        console.print(f"[dim]Provider queries routed through proxy {config.describe()['proxy']} (opsec).[/]")
    console.print(
        f"[bold]Ariadne[/] UI running at [cyan]http://{args.host}:{args.port}[/]  (Ctrl+C to stop)"
    )
    app.run(host=args.host, port=args.port, debug=False)


def main(argv: list[str] | None = None) -> None:
    try:  # ensure Unicode box-drawing / ellipsis render on Windows consoles
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(prog="ariadne", description="Blockchain money-flow tracer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    tr = sub.add_parser("trace", help="Trace value flow from an address")
    tr.add_argument("address")
    tr.add_argument("--chain", default="btc", choices=_CHAINS,
                    help="asset / chain to trace (default btc)")
    tr.add_argument("--depth", type=int, default=2, help="hops to follow (default 2)")
    tr.add_argument("--max-branch", type=int, default=8, help="max recipients to expand per address")
    tr.add_argument("--min-amount", type=float, default=0.001, help="ignore flows smaller than this (asset units)")
    tr.add_argument("--max-txs", type=int, default=200, help="max txs to pull per address")
    tr.add_argument("--direction", default="forward", choices=["forward", "backward"], help="trace value flow forward or backward")
    tr.add_argument("--follow", default="bfs", choices=["bfs", "dirty"],
                    help="expansion strategy: bfs (breadth-first, default) or dirty (best-first, follows the dirty money)")
    tr.add_argument("--taint-model", default="haircut", choices=["haircut", "poison", "fifo"],
                    help="taint methodology: haircut (proportional, default), poison (maximal), fifo (Clayton's Case)")
    tr.add_argument("--service-threshold", type=int, default=3000, help="activity above which an address is a service")
    tr.add_argument("--workers", type=int, default=4, help="concurrent fetch threads per BFS level (default 4)")
    tr.add_argument("--labels", action="append", help="extra label JSON file (repeatable)")
    tr.add_argument("--discover-deposits", action="store_true",
                    help="name unlabelled cash-outs via exchange deposit-address discovery")
    tr.add_argument("--no-fiat", action="store_true", help="skip USD/EUR valuation (no price lookups)")
    tr.add_argument("--report", action="store_true", help="write JSON/DOT/HTML + court-ready expert report")
    tr.add_argument("--no-sign", action="store_true", help="skip the Ed25519-signed evidence bundle when reporting")
    tr.add_argument("--case-ref", help="case reference to stamp on the expert report")
    tr.add_argument("--outdir", default="reports", help="report output directory")

    ul = sub.add_parser("update-labels", help="Import third-party attribution data")
    ul.add_argument("--ofac", action="store_true", help="import OFAC SDN sanctioned crypto addresses")
    ul.add_argument("--out", help="output label file (default: bundled ofac_sanctioned.json)")

    sub.add_parser("update-intel", help="Pull OFAC sanctions + scam intelligence feeds into the label store")

    sub.add_parser("validate", help="Run the known-answer validation corpus and score accuracy")

    sub.add_parser("adversarial", help="Deterministic per-technique detection scorecard (offline, reproducible)")

    me = sub.add_parser("measure", help="Measure false-positive / false-negative rates (confusion matrix)")
    me.add_argument("--sample", type=int, default=40, help="positives per category")
    me.add_argument("--negatives", type=int, default=60, help="legitimate negatives")

    bm = sub.add_parser("benchmark", help="Per-category accuracy report (precision/recall/FP/FN), optionally signed")
    bm.add_argument("--sample", type=int, default=100, help="positives per category")
    bm.add_argument("--negatives", type=int, default=150, help="legitimate negatives")
    bm.add_argument("--report", action="store_true", help="write JSON + Markdown accuracy report")
    bm.add_argument("--sign", action="store_true", help="Ed25519-sign the JSON accuracy report")
    bm.add_argument("--outdir", default="reports")

    iv = sub.add_parser("investigate", help="Trace many seeds into ONE combined graph (shared infra, hubs, dossier)")
    iv.add_argument("--name", required=True, help="operation name, e.g. theseus")
    iv.add_argument("--seeds", required=True, help="file with one address per line (optional ',chain')")
    iv.add_argument("--depth", type=int, default=3)
    iv.add_argument("--max-branch", type=int, default=4)
    iv.add_argument("--min-amount", type=float, default=0.01)
    iv.add_argument("--max-txs", type=int, default=150)
    iv.add_argument("--service-threshold", type=int, default=3000)
    iv.add_argument("--workers", type=int, default=4)
    iv.add_argument("--outdir", default="reports/investigations")

    op = sub.add_parser("operation", help="Batch-investigate a list of wallets and connect them into a ring")
    op.add_argument("--name", required=True, help="operation name, e.g. theseus")
    op.add_argument("--wallets", required=True, help="file with one address per line (optional ',chain')")
    op.add_argument("--depth", type=int, default=3)
    op.add_argument("--max-branch", type=int, default=3)
    op.add_argument("--min-amount", type=float, default=0.01)
    op.add_argument("--max-txs", type=int, default=200)
    op.add_argument("--service-threshold", type=int, default=3000)
    op.add_argument("--outdir", default="reports/operations")

    mon = sub.add_parser("monitor", help="Live-monitor a chain's newest block and flag suspicious txs")
    mon.add_argument("--chain", default="btc", choices=_CHAINS)
    mon.add_argument("--block", type=int, help="specific block height (default: latest)")
    mon.add_argument("--sample", type=int, default=25, help="max txs to scan from the block")
    mon.add_argument("--threshold", type=int, default=25, help="suspicion score to flag")
    mon.add_argument("--large-value", type=float, default=50.0, help="asset-unit amount treated as large")
    mon.add_argument("--auto-trace", action="store_true", help="auto-investigate flagged txs")
    mon.add_argument("--trace-depth", type=int, default=3)
    mon.add_argument("--max-investigations", type=int, default=3)
    mon.add_argument("--blocks", type=int, default=0, help="backfill: scan the last N blocks")
    mon.add_argument("--watch", action="store_true", help="continuously watch for new blocks")
    mon.add_argument("--poll-interval", type=int, default=30, help="seconds between polls in --watch")
    mon.add_argument("--watch-max", type=int, default=3, help="stop after this many blocks in --watch")
    mon.add_argument("--mempool", action="store_true", help="scan unconfirmed mempool txs instead of a block")
    mon.add_argument("--daemon", action="store_true", help="run continuously (24/7), alerting the operator")
    mon.add_argument("--webhook", help="POST each alert to this URL (Slack / Discord / SIEM)")
    mon.add_argument("--alert-log", help="append alerts to this JSONL file (default reports/alerts/alerts.jsonl)")
    mon.add_argument("--labels", action="append", help="extra label JSON file (repeatable)")

    cl = sub.add_parser("cluster", help="Find every wallet controlled by the same entity as an address")
    cl.add_argument("address")
    cl.add_argument("--chain", default="btc", choices=_CHAINS)
    cl.add_argument("--max-addresses", type=int, default=300, help="cap on cluster size")
    cl.add_argument("--max-txs", type=int, default=100, help="max txs to read per address")
    cl.add_argument("--report", action="store_true", help="write a JSON cluster report")
    cl.add_argument("--outdir", default="reports")
    cl.add_argument("--labels", action="append", help="extra label JSON file (repeatable)")

    cs = sub.add_parser("case", help="Manage investigation cases and evidence bundles")
    cs.add_argument("action", choices=["create", "list", "export", "add-note", "add-evidence"])
    cs.add_argument("--case-id")
    cs.add_argument("--title")
    cs.add_argument("--note")
    cs.add_argument("--tag", action="append")
    cs.add_argument("--detail", help="evidence detail for add-evidence")
    cs.add_argument("--store", default="reports/cases.json")
    cs.add_argument("--outdir", default="reports/evidence")

    sv = sub.add_parser("serve", help="Launch the Ariadne web UI")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--auth-token", help="Single operator bearer token (admin role)")
    sv.add_argument("--auth-tokens", help="Multi-user tokens as 'token:role,token:role' (roles: viewer/analyst/admin)")
    sv.add_argument("--audit-log", help="Path to the append-only JSONL audit log")

    rc = sub.add_parser("recall", help="Recall what Ariadne already knows about an address")
    rc.add_argument("address")

    sub.add_parser("knowledge", help="Knowledge-base stats and tamper-evidence check")

    ve = sub.add_parser("verify-evidence", help="Verify an Ed25519-signed evidence bundle")
    ve.add_argument("bundle", help="path to a *.evidence.json bundle")

    rp = sub.add_parser("replay", help="Re-derive a trace OFFLINE from the preserved cache and prove it matches")
    rp.add_argument("bundle", help="path to a *.evidence.json bundle")

    at = sub.add_parser("attribute", help="Name an unlabelled address via exchange deposit-address discovery")
    at.add_argument("address")
    at.add_argument("--chain", default="btc", choices=_CHAINS)
    at.add_argument("--max-txs", type=int, default=200)

    idb = sub.add_parser("intel-db", help="Versioned attribution store: stats, import, per-address history")
    idb.add_argument("--import-feeds", action="store_true", help="import the current label feeds into the store")
    idb.add_argument("--address", help="show the attribution history for one address")

    co = sub.add_parser("correlate", help="Correlate bridge deposits/withdrawals across chains (amount + time)")
    co.add_argument("reports", nargs="+", help="trace report JSON files (from two+ chains for cross-chain hops)")
    co.add_argument("--tolerance", type=float, default=0.02, help="max relative amount difference (default 2%%)")
    co.add_argument("--max-delay", type=int, default=3600, help="max seconds between deposit and withdrawal")
    co.add_argument("--top", type=int, default=20)

    gr = sub.add_parser("graph", help="Link analysis over the accumulated flow graph (hubs, rings, paths)")
    gr.add_argument("--path", nargs=2, metavar=("SRC", "DST"), help="find a money path between two addresses")
    gr.add_argument("--undirected", action="store_true", help="ignore flow direction for path finding")
    gr.add_argument("--top", type=int, default=10, help="how many hubs / rings to show")
    gr.add_argument("--min-community", type=int, default=3, help="minimum ring size to report")

    tl = sub.add_parser("timeline", help="Temporal / behavioural profile of an address (active hours, timezone, velocity)")
    tl.add_argument("address")
    tl.add_argument("--chain", default="btc", choices=_CHAINS)
    tl.add_argument("--max-txs", type=int, default=200)

    sc = sub.add_parser("screen", help="Sanctions / illicit-exposure screening for an address (compliance verdict)")
    sc.add_argument("address")
    sc.add_argument("--chain", default="btc", choices=_CHAINS)
    sc.add_argument("--depth", type=int, default=3)
    sc.add_argument("--max-branch", type=int, default=6)
    sc.add_argument("--min-amount", type=float, default=0.001)
    sc.add_argument("--workers", type=int, default=4)

    en = sub.add_parser("entity", help="Resolve and profile the entity (actor) behind an address")
    en.add_argument("address")
    en.add_argument("--chain", default="btc", choices=_CHAINS)
    en.add_argument("--max-addresses", type=int, default=300)
    en.add_argument("--max-txs", type=int, default=100)

    lb = sub.add_parser("label", help="Record analyst manual attribution for an address (flows into future traces)")
    lb.add_argument("address")
    lb.add_argument("--category", required=True, help="sanctioned/scam/exchange/atm/mixer/service/...")
    lb.add_argument("--name", help="entity name, e.g. 'Courier wallet'")
    lb.add_argument("--chain", default="btc", choices=_CHAINS)
    lb.add_argument("--note", help="provenance / justification")

    w = sub.add_parser("watch", help="Targeted watchlist — alert when a suspect address moves")
    w.add_argument("action", choices=["add", "remove", "list", "scan"])
    w.add_argument("address", nargs="?")
    w.add_argument("--chain", default="btc", choices=_CHAINS)
    w.add_argument("--note", help="analyst note for this target")
    w.add_argument("--priority", type=int, default=1)
    w.add_argument("--auto-trace", action="store_true", help="auto-trace addresses that moved (scan)")

    asy = sub.add_parser("atm-sync", help="Sync physical crypto-ATM locations from OpenStreetMap (keyless)")
    asy.add_argument("--bbox", help="limit region: 'south,west,north,east' (default worldwide)")
    asy.add_argument("--timeout", type=int, default=180, help="Overpass query timeout seconds")

    atmp = sub.add_parser("atm", help="Query the crypto-ATM registry (near a point, by operator, or list operators)")
    atmp.add_argument("--near", help="find machines near 'lat,lon'")
    atmp.add_argument("--radius", type=float, default=5.0, help="search radius km for --near")
    atmp.add_argument("--operator", help="list machines for an operator (substring match)")
    atmp.add_argument("--operators", action="store_true", help="list top operators by machine count")
    atmp.add_argument("--limit", type=int, default=25)

    ap = sub.add_parser("autopilot", help="Autonomous loop: watchlist movement alerts + scheduled feed refresh")
    ap.add_argument("--watch-interval", type=int, default=300, help="seconds between watchlist polls")
    ap.add_argument("--feed-interval", type=int, default=86400, help="seconds between intel-feed refreshes")
    ap.add_argument("--auto-trace", action="store_true", help="auto-trace addresses that move")
    ap.add_argument("--webhook", help="POST alerts to this URL (Slack / Discord / SIEM)")
    ap.add_argument("--alert-log", help="append alerts to this JSONL file")
    ap.add_argument("--once", action="store_true", help="run a single cycle and exit (for cron)")

    sub.add_parser("config", help="Show deployment config: enabled chains, proxy, self-hosted endpoints")

    args = parser.parse_args(argv)
    console = Console()
    handlers = {
        "trace": cmd_trace,
        "update-labels": cmd_update_labels,
        "update-intel": cmd_update_intel,
        "validate": cmd_validate,
        "adversarial": cmd_adversarial,
        "measure": cmd_measure,
        "benchmark": cmd_benchmark,
        "operation": cmd_operation,
        "investigate": cmd_investigate,
        "monitor": cmd_monitor,
        "cluster": cmd_cluster,
        "case": cmd_case,
        "serve": cmd_serve,
        "recall": cmd_recall,
        "knowledge": cmd_knowledge,
        "verify-evidence": cmd_verify_evidence,
        "replay": cmd_replay,
        "attribute": cmd_attribute,
        "intel-db": cmd_intel_db,
        "graph": cmd_graph,
        "correlate": cmd_correlate,
        "timeline": cmd_timeline,
        "screen": cmd_screen,
        "entity": cmd_entity,
        "label": cmd_label,
        "watch": cmd_watch,
        "autopilot": cmd_autopilot,
        "atm-sync": cmd_atm_sync,
        "atm": cmd_atm,
        "config": cmd_config,
    }
    try:
        handlers[args.cmd](args, console)
    except ValueError as exc:  # e.g. a gated/disabled chain — show a clean message
        console.print(f"[red]{exc}[/]")


if __name__ == "__main__":
    main()
