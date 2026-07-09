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

from .cache import ProvenanceCache
from .cases import CaseStore, InvestigationCase
from .knowledge import KnowledgeStore
from .core.cluster import Clusterer
from .core.confidence import assess as assess_confidence
from .core.patterns import detect_offramps, detect_peel_chains
from .core.taint import compute_taint
from .core.trace import Tracer
from .enrich import ofac
from .enrich import feeds
from .enrich.labels import (
    LabelStore,
    default_labels_path,
    intel_labels_path,
    ofac_labels_path,
    write_labels,
)
from .models import NodeType, is_valid_address
from .monitor.monitor import Monitor
from .providers.bitcoin import BlockstreamProvider
from .providers.blockchair import BlockchairProvider
from .providers.ethereum import EthereumProvider
from .providers.monero import MoneroProvider
from .providers.tron import TronProvider
from .report import report as report_mod


def short(addr: str) -> str:
    return addr if len(addr) <= 16 else f"{addr[:8]}..{addr[-6:]}"


def build_provider(chain: str, cache: ProvenanceCache):
    chain = chain.lower()
    if chain == "btc":
        return BlockstreamProvider(cache=cache)
    if chain in ("ltc", "doge"):
        return BlockchairProvider(chain=chain, cache=cache)
    if chain == "xmr":
        return MoneroProvider(cache=cache)
    if chain in ("trx", "tron"):
        return TronProvider(cache=cache)
    if chain in ("eth", "usdt", "usdc"):
        asset = "ETH" if chain == "eth" else chain.upper()
        return EthereumProvider(asset=asset, cache=cache)
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
    console.print(f"[dim]Loaded {len(labels)} address labels.[/]")

    cache = ProvenanceCache()
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
            )
    compute_taint(result)
    render(result, console)

    report = report_mod.build_report(result)
    inv_id = knowledge.record_trace(report, args.chain)
    console.print(f"[dim]Recorded as investigation #{inv_id} in the tamper-evident knowledge base.[/]")
    knowledge.close()

    if args.report:
        safe = args.address.lower().replace("0x", "")[:12]
        basename = f"{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        paths = report_mod.write_all(result, Path(args.outdir), basename)
        console.print()
        for kind, path in paths.items():
            console.print(f"[green]{kind.upper():>4}[/] report: {path}")

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


def cmd_serve(args, console: Console) -> None:
    from .web.app import create_app

    if args.host not in ("127.0.0.1", "localhost"):
        console.print(
            "[yellow]Warning:[/] binding to a non-loopback address exposes the UI to your network. "
            "The API has no authentication — only do this behind a trusted network or VPN."
        )
    auth_token = args.auth_token or None
    audit_log_path = Path(args.audit_log) if args.audit_log else None
    app = create_app(auth_token=auth_token, audit_log_path=audit_log_path)
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
    tr.add_argument("--chain", default="btc", choices=["btc", "eth", "usdt", "usdc", "trx", "ltc", "doge", "xmr"],
                    help="asset / chain to trace (default btc)")
    tr.add_argument("--depth", type=int, default=2, help="hops to follow (default 2)")
    tr.add_argument("--max-branch", type=int, default=8, help="max recipients to expand per address")
    tr.add_argument("--min-amount", type=float, default=0.001, help="ignore flows smaller than this (asset units)")
    tr.add_argument("--max-txs", type=int, default=200, help="max txs to pull per address")
    tr.add_argument("--direction", default="forward", choices=["forward", "backward"], help="trace value flow forward or backward")
    tr.add_argument("--service-threshold", type=int, default=3000, help="activity above which an address is a service")
    tr.add_argument("--labels", action="append", help="extra label JSON file (repeatable)")
    tr.add_argument("--report", action="store_true", help="write JSON/DOT/HTML reports")
    tr.add_argument("--outdir", default="reports", help="report output directory")

    ul = sub.add_parser("update-labels", help="Import third-party attribution data")
    ul.add_argument("--ofac", action="store_true", help="import OFAC SDN sanctioned crypto addresses")
    ul.add_argument("--out", help="output label file (default: bundled ofac_sanctioned.json)")

    sub.add_parser("update-intel", help="Pull OFAC sanctions + scam intelligence feeds into the label store")

    sub.add_parser("validate", help="Run the known-answer validation corpus and score accuracy")

    me = sub.add_parser("measure", help="Measure false-positive / false-negative rates (confusion matrix)")
    me.add_argument("--sample", type=int, default=40, help="positives per category")
    me.add_argument("--negatives", type=int, default=60, help="legitimate negatives")

    mon = sub.add_parser("monitor", help="Live-monitor a chain's newest block and flag suspicious txs")
    mon.add_argument("--chain", default="btc", choices=["btc", "eth", "usdt", "usdc", "trx", "ltc", "doge", "xmr"])
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
    cl.add_argument("--chain", default="btc", choices=["btc", "eth", "usdt", "usdc", "trx", "ltc", "doge", "xmr"])
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
    sv.add_argument("--auth-token", help="Require an auth bearer token for API access")
    sv.add_argument("--audit-log", help="Path to the append-only JSONL audit log")

    rc = sub.add_parser("recall", help="Recall what Ariadne already knows about an address")
    rc.add_argument("address")

    sub.add_parser("knowledge", help="Knowledge-base stats and tamper-evidence check")

    args = parser.parse_args(argv)
    console = Console()
    if args.cmd == "trace":
        cmd_trace(args, console)
    elif args.cmd == "update-labels":
        cmd_update_labels(args, console)
    elif args.cmd == "update-intel":
        cmd_update_intel(args, console)
    elif args.cmd == "validate":
        cmd_validate(args, console)
    elif args.cmd == "measure":
        cmd_measure(args, console)
    elif args.cmd == "monitor":
        cmd_monitor(args, console)
    elif args.cmd == "cluster":
        cmd_cluster(args, console)
    elif args.cmd == "case":
        cmd_case(args, console)
    elif args.cmd == "serve":
        cmd_serve(args, console)
    elif args.cmd == "recall":
        cmd_recall(args, console)
    elif args.cmd == "knowledge":
        cmd_knowledge(args, console)


if __name__ == "__main__":
    main()
