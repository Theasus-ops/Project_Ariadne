"""Ariadne web UI backend.

A small Flask app that exposes the engine (trace / cluster / monitor) as JSON
endpoints and serves the single-page front end. It is designed to run **locally**
(bind 127.0.0.1). Hardening:

  * every address is validated and every chain is whitelisted before use;
  * all numeric parameters are clamped to sane bounds (no unbounded traces);
  * request bodies are size-capped;
  * errors return a generic message -- never a stack trace.
"""

from __future__ import annotations

import hmac
import json
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .. import config
from ..cache import ProvenanceCache
from ..cases import CaseStore, InvestigationCase
from ..core.cluster import Clusterer
from ..core.taint import compute_taint
from ..core.trace import Tracer
from ..enrich.atm import ATMRegistry, atm_intel_for_report
from ..enrich.labels import LabelStore, default_labels_path, intel_labels_path, ofac_labels_path
from ..knowledge import KnowledgeStore
from ..models import is_valid_address
from ..monitor.monitor import Monitor
from ..providers.bitcoin import BlockstreamProvider
from ..providers.blockchair import BlockchairProvider
from ..providers.ethereum import EthereumProvider
from ..providers.monero import MoneroProvider
from ..providers.tron import TronProvider
from ..report import report as report_mod
from ..security import AuditLogger

_STATIC = Path(__file__).resolve().parent / "static"
_CHAINS = ("btc", "eth", "usdt", "usdc", "trx", "ltc", "doge", "xmr")


class BadInput(Exception):
    """Raised for client input we refuse; surfaced as HTTP 400."""


def _labels() -> LabelStore:
    return LabelStore.load(default_labels_path(), ofac_labels_path(), intel_labels_path())


def _provider(chain: str, cache: ProvenanceCache):
    kw = config.provider_kwargs(chain)
    if chain == "btc":
        return BlockstreamProvider(cache=cache, **kw)
    if chain in ("ltc", "doge"):
        return BlockchairProvider(chain=chain, cache=cache, **kw)
    if chain == "xmr":
        return MoneroProvider(cache=cache)
    if chain in ("trx", "tron"):
        return TronProvider(cache=cache, **kw)
    return EthereumProvider(asset=("ETH" if chain == "eth" else chain.upper()), cache=cache, **kw)


def _chain(data: dict) -> str:
    chain = str(data.get("chain") or "btc").lower()
    if chain not in _CHAINS:
        raise BadInput("unsupported chain")
    if not config.is_enabled(chain):
        raise BadInput(config.gating_message(chain))
    return chain


def _address(data: dict, chain: str) -> str:
    address = str(data.get("address") or "").strip()
    if not is_valid_address(address, chain):
        raise BadInput("invalid address format")
    return address


def _clamp_int(data: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(data.get(key, default))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def _clamp_float(data: dict, key: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float(data.get(key, default))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def create_app(
    auth_token: str | None = None,
    audit_log_path: str | Path | None = None,
    case_store_path: str | Path | None = None,
    auth_tokens: dict | None = None,
) -> Flask:
    app = Flask(__name__, static_folder=str(_STATIC))
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # cap request bodies
    # Roles are bound to TOKENS on the server, never taken from a client header.
    # A single operator token is an admin; multi-user deployments pass auth_tokens.
    token_roles: dict[str, str] = {}
    if auth_token:
        token_roles[auth_token] = "admin"
    if auth_tokens:
        for tok, role in dict(auth_tokens).items():
            token_roles[str(tok)] = str(role)
    app.config["TOKEN_ROLES"] = token_roles
    app.config["AUDIT_LOGGER"] = AuditLogger(audit_log_path)
    app.config["CASE_STORE"] = CaseStore(case_store_path)
    app.config["ROLE_MAP"] = {
        "viewer": {"trace", "cluster"},
        "analyst": {"trace", "cluster", "monitor", "cases"},
        "admin": {"trace", "cluster", "monitor", "cases", "export"},
    }

    @app.errorhandler(BadInput)
    def _on_bad(exc):
        if str(exc) == "authentication required":
            return jsonify({"error": str(exc)}), 401
        if str(exc) == "forbidden":
            return jsonify({"error": str(exc)}), 403
        return jsonify({"error": str(exc)}), 400

    @app.errorhandler(Exception)
    def _on_error(exc):
        app.logger.exception("request failed")
        return jsonify({"error": "internal error"}), 500

    def _require_auth(capability: str | None = None):
        """Authenticate the bearer token and authorise the required capability.

        The operator's role is resolved from the *token* server-side (constant-time
        comparison) — never from a client-supplied header, which would be trivially
        spoofable. If no tokens are configured the API is open (loopback dev use).
        """
        token_roles = app.config.get("TOKEN_ROLES") or {}
        if not token_roles:
            return None
        header = request.headers.get("Authorization", "")
        presented = header[7:] if header.startswith("Bearer ") else ""
        role = None
        for tok, r in token_roles.items():
            if hmac.compare_digest(tok, presented):
                role = r
        if role is None:
            raise BadInput("authentication required")
        if capability:
            allowed = app.config.get("ROLE_MAP", {}).get(role, set())
            if capability not in allowed:
                raise BadInput("forbidden")
        return role

    def _audit(event: str, action: str, details: dict | None = None) -> None:
        logger = app.config.get("AUDIT_LOGGER")
        if logger is not None:
            logger.log(event, request.remote_addr or "unknown", action, details)

    @app.get("/")
    def index():
        return send_from_directory(_STATIC, "index.html")

    @app.get("/api/health")
    def api_health():
        return jsonify({
            "status": "ok",
            "service": "ariadne",
            "chains": list(_CHAINS),
            "enabled_chains": sorted(config.enabled_chains()),
            "auth": bool(app.config.get("TOKEN_ROLES")),
        })

    @app.get("/api/knowledge")
    def api_knowledge():
        _require_auth("trace")
        knowledge = KnowledgeStore()
        try:
            return jsonify(
                {"stats": knowledge.stats(), "integrity": knowledge.verify_integrity(), "recent": knowledge.recent(10)}
            )
        finally:
            knowledge.close()

    @app.post("/api/recall")
    def api_recall():
        _require_auth("trace")
        data = request.get_json(silent=True) or {}
        address = str(data.get("address") or "").strip()
        if not is_valid_address(address):
            raise BadInput("invalid address format")
        knowledge = KnowledgeStore()
        try:
            return jsonify(knowledge.recall(address))
        finally:
            knowledge.close()

    @app.post("/api/trace")
    def api_trace():
        _require_auth("trace")
        _audit("request", "trace", {"chain": (request.get_json(silent=True) or {}).get("chain")})
        data = request.get_json(silent=True) or {}
        chain = _chain(data)
        address = _address(data, chain)
        cache = ProvenanceCache()
        try:
            provider = _provider(chain, cache)
            tracer = Tracer(
                provider,
                label_store=_labels(),
                max_txs_per_address=_clamp_int(data, "max_txs", 150, 10, 1000),
                workers=_clamp_int(data, "workers", 4, 1, 16),
            )
            decimals = provider.asset_info.decimals
            min_value = int(_clamp_float(data, "min_amount", 0.01, 0.0, 1e12) * (10 ** decimals))
            direction = str(data.get("direction") or "forward").lower()
            if direction == "backward":
                result = tracer.trace_backward(
                    address,
                    depth=_clamp_int(data, "depth", 3, 1, 6),
                    min_value=min_value,
                    max_branch=_clamp_int(data, "max_branch", 4, 1, 12),
                )
            else:
                result = tracer.trace_forward(
                    address,
                    depth=_clamp_int(data, "depth", 3, 1, 6),
                    min_value=min_value,
                    max_branch=_clamp_int(data, "max_branch", 4, 1, 12),
                )
            model = str(data.get("taint_model") or "haircut").lower()
            if model not in ("haircut", "poison", "fifo"):
                model = "haircut"
            compute_taint(result, model=model)
            report = report_mod.build_report(result)
            # Crypto-ATM geolocation enrichment (if a local registry has been synced).
            registry = ATMRegistry()
            try:
                if registry.stats()["machines"] > 0:
                    intel = atm_intel_for_report(report, registry)
                    if intel:
                        report["atm_intel"] = intel
            finally:
                registry.close()
            knowledge = KnowledgeStore()
            try:
                report["prior_knowledge"] = knowledge.recall(provider.normalize(address))
                report["investigation_id"] = knowledge.record_trace(report, chain)
            finally:
                knowledge.close()
            return jsonify(report)
        finally:
            cache.close()

    @app.post("/api/cluster")
    def api_cluster():
        _require_auth("cluster")
        _audit("request", "cluster", {"chain": (request.get_json(silent=True) or {}).get("chain")})
        data = request.get_json(silent=True) or {}
        chain = _chain(data)
        address = _address(data, chain)
        cache = ProvenanceCache()
        try:
            provider = _provider(chain, cache)
            labels = _labels()
            clusterer = Clusterer(
                provider, label_store=labels, max_addresses=_clamp_int(data, "max_addresses", 200, 1, 1000)
            )
            cluster = clusterer.cluster(address)
            out = cluster.as_dict()
            out["labels"] = {
                a: {"name": labels.get(a).name, "category": labels.get(a).category.value}
                for a in out["entity_wallets"]
                if labels.get(a)
            }
            return jsonify(out)
        finally:
            cache.close()

    @app.post("/api/monitor")
    def api_monitor():
        _require_auth("monitor")
        _audit("request", "monitor", {"chain": (request.get_json(silent=True) or {}).get("chain")})
        data = request.get_json(silent=True) or {}
        chain = _chain(data)
        cache = ProvenanceCache()
        try:
            provider = _provider(chain, cache)
            monitor = Monitor(
                provider,
                _labels(),
                threshold=_clamp_int(data, "threshold", 20, 1, 100),
                sample=_clamp_int(data, "sample", 25, 1, 100),
                large_value_units=_clamp_float(data, "large_value", 20, 0.0, 1e12),
            )
            if data.get("mempool"):
                height, scored = None, monitor.poll_mempool()
            else:
                raw = data.get("block")
                block = int(raw) if (isinstance(raw, int) or (isinstance(raw, str) and raw.isdigit())) else None
                height, scored = monitor.poll_block(block)
            scored.sort(key=lambda s: s.score.total, reverse=True)
            return jsonify(
                {
                    "height": height,
                    "mempool": bool(data.get("mempool")),
                    "chain": provider.asset_info.symbol,
                    "threshold": monitor.threshold,
                    "count": len(scored),
                    "flagged": len(monitor.suspicious(scored)),
                    "transactions": [
                        {
                            "txid": s.tx.txid,
                            "address": Monitor.seed_address(s),
                            "score": s.score.total,
                            "level": s.score.level,
                            "reasons": [r.split("] ", 1)[-1] for r in s.score.reasons],
                        }
                        for s in scored
                    ],
                }
            )
        finally:
            cache.close()

    @app.post("/api/cases")
    def api_cases():
        _require_auth("cases")
        data = request.get_json(silent=True) or {}
        store = app.config.get("CASE_STORE")
        case = InvestigationCase(data.get("case_id") or "case-1", data.get("title") or "Untitled case")
        case.investigator = data.get("investigator") or case.investigator
        case.add_note(data.get("note") or "Case opened")
        if data.get("evidence"):
            case.add_evidence(data.get("evidence"))
        if data.get("tags"):
            for tag in data.get("tags", []):
                case.add_tag(tag)
        return jsonify(store.save_case(case))

    @app.get("/api/cases")
    def api_list_cases():
        _require_auth("cases")
        store = app.config.get("CASE_STORE")
        return jsonify(store.list_cases())

    @app.post("/api/cases/<case_id>/update")
    def api_update_case(case_id: str):
        _require_auth("cases")
        data = request.get_json(silent=True) or {}
        store = app.config.get("CASE_STORE")
        existing = store.load_case(case_id)
        if existing is None:
            raise BadInput("case not found")
        case = InvestigationCase(existing["case_id"], existing["title"], existing.get("investigator", "operator"))
        case.notes = list(existing.get("notes", []))
        case.evidence = list(existing.get("evidence", []))
        case.tags = list(existing.get("tags", []))
        case.timeline = list(existing.get("timeline", []))
        case.created_at = existing.get("created_at", case.created_at)
        case.updated_at = existing.get("updated_at", case.updated_at)
        if data.get("note"):
            case.add_note(str(data["note"]))
        if data.get("evidence"):
            case.add_evidence(data.get("evidence"))
        if data.get("tags"):
            for tag in data.get("tags", []):
                case.add_tag(tag)
        return jsonify(store.save_case(case))

    @app.post("/api/cases/<case_id>/export")
    def api_export_case(case_id: str):
        _require_auth("export")
        store = app.config.get("CASE_STORE")
        out = store.export_bundle(case_id, Path("reports/evidence"))
        return jsonify({"path": str(out), "signature": json.loads(out.read_text(encoding="utf-8")).get("signature")})

    return app
