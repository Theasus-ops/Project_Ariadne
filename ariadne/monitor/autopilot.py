"""Autopilot — continuous, autonomous intelligence.

The block daemon watches new transactions; autopilot watches *the whole operation*.
On a schedule it:

  * polls the **watchlist** and alerts the instant a suspect address moves (and can
    auto-trace it);
  * periodically **refreshes the intelligence feeds** so attribution never goes stale;
  * persists when it last did each, so a restart resumes cleanly.

It is deliberately small and dependency-free: the heavy lifting (watchlist polling,
feed pulls, alerting) is the same code the CLI uses, wired into one supervised loop.
Everything is injectable, so the cycle logic is fully unit-testable offline.
"""

from __future__ import annotations

import json
import time
from pathlib import Path


def _default_refresh_feeds() -> int:
    """Pull all public feeds, rewrite the intel labels, mirror to the store."""
    from ..enrich import feeds
    from ..enrich.attribution import AttributionStore
    from ..enrich.labels import intel_labels_path, write_labels

    labels = feeds.fetch_all()
    if not labels:
        return 0
    write_labels(labels, intel_labels_path(), note="autopilot feed refresh")
    store = AttributionStore()
    try:
        store.import_labels(labels, provenance="autopilot feed refresh")
    finally:
        store.close()
    return len(labels)


class Autopilot:
    def __init__(
        self,
        watchlist,
        build_provider,
        notifier,
        cache_factory,
        watch_interval: int = 300,
        feed_interval: int = 86400,
        state_path: str | Path = "knowledge/autopilot_state.json",
        refresh_feeds=None,
        auto_trace=None,
    ) -> None:
        self.watchlist = watchlist
        self.build_provider = build_provider
        self.notifier = notifier
        self.cache_factory = cache_factory
        self.watch_interval = watch_interval
        self.feed_interval = feed_interval
        self.state_path = Path(state_path)
        self.refresh_feeds = refresh_feeds or _default_refresh_feeds
        self.auto_trace = auto_trace  # optional callable(alert) for a movement
        self.state = self._load_state()

    def _load_state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_state(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        except Exception:
            pass

    def cycle(self, now: float | None = None) -> dict:
        """One supervision pass: watchlist movement + due feed refresh."""
        now = time.time() if now is None else now
        alerts: list[dict] = []

        cache = self.cache_factory()
        try:
            for mv in self.watchlist.check_movements(self.build_provider, cache):
                event = {
                    "type": "watchlist_movement", "time": now,
                    "address": mv["address"], "chain": mv["chain"],
                    "new_transactions": mv["new_transactions"], "note": mv.get("note", ""),
                }
                if self.auto_trace:
                    try:
                        event["report"] = self.auto_trace(mv, cache)
                    except Exception:
                        pass
                self.notifier.alert(event)
                alerts.append(event)
        finally:
            try:
                cache.close()
            except Exception:
                pass

        refreshed = False
        if now - float(self.state.get("last_feed_refresh", 0)) >= self.feed_interval:
            try:
                n = self.refresh_feeds()
                self.state["last_feed_refresh"] = now
                refreshed = True
                self.notifier.alert({"type": "feeds_refreshed", "time": now, "labels": n})
            except Exception:
                pass

        self.state["last_cycle"] = now
        self._save_state()
        return {"watch_alerts": len(alerts), "feeds_refreshed": refreshed, "alerts": alerts}

    def run(self, max_cycles: int | None = None) -> None:
        cycles = 0
        while max_cycles is None or cycles < max_cycles:
            self.cycle()
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            time.sleep(self.watch_interval)
