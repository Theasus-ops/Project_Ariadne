"""24/7 monitoring daemon.

Watches a chain continuously: each poll processes any blocks that appeared since
the last one, scores every transaction, and for anything above the alert
threshold it notifies the operator, auto-investigates, and attaches the top
recommended action from the investigation brief.

Robustness for a long-running process:
  * de-duplication so the same transaction is never alerted twice;
  * persisted state (last block + seen txids) so a restart resumes cleanly.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from ..logging_setup import get_logger
from .monitor import Monitor
from .notify import Notifier

log = get_logger("daemon")


class MonitorDaemon:
    def __init__(
        self,
        monitor: Monitor,
        notifier: Notifier,
        poll_interval: int = 30,
        auto_trace: bool = True,
        max_investigations: int = 3,
        state_path: str | Path = "knowledge/monitor_state.json",
    ) -> None:
        self.monitor = monitor
        self.notifier = notifier
        self.poll_interval = poll_interval
        self.auto_trace = auto_trace
        self.max_investigations = max_investigations
        self.state_path = Path(state_path)
        self._seen: set[str] = set()
        self._last: int | None = None
        self._load_state()

    def _load_state(self) -> None:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            self._last = data.get("last_height")
            self._seen = set(data.get("seen", []))
        except FileNotFoundError:
            pass  # first run — start from the current tip
        except (OSError, ValueError) as exc:
            log.warning("could not read monitor state %s: %s", self.state_path, exc)

    def _save_state(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps({"last_height": self._last, "seen": list(self._seen)[-5000:]}),
                encoding="utf-8",
            )
        except OSError as exc:
            log.warning("could not persist monitor state %s: %s", self.state_path, exc)

    def _event(self, height, scored, do_trace: bool) -> dict:
        tx = scored.tx
        event = {
            "time": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            "chain": self.monitor.provider.asset_info.symbol,
            "block": height,
            "txid": tx.txid,
            "score": scored.score.total,
            "level": scored.score.level,
            "reasons": [r.split("] ", 1)[-1] for r in scored.score.reasons],
        }
        if do_trace:
            try:
                paths = self.monitor.investigate(scored)
            except Exception as exc:  # noqa: BLE001 — a failed auto-trace still yields the alert
                log.warning("auto-investigation of %s failed: %s", tx.txid, exc)
                paths = None
            if paths:
                event["report"] = str(paths["json"])
                try:
                    rep = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
                    brief = rep.get("brief", {})
                    event["risk_level"] = brief.get("risk_level")
                    event["risk_score"] = brief.get("risk_score")
                    steps = brief.get("recommended_next_steps") or []
                    event["recommended_action"] = steps[0] if steps else None
                except (OSError, ValueError) as exc:
                    log.debug("could not attach brief for %s: %s", tx.txid, exc)
        return event

    def poll_once(self) -> list[dict]:
        """Process any new blocks since last poll; return the alerts raised."""
        tip = self.monitor.provider.latest_block_height()
        if self._last is None:
            self._last = tip - 1
        raised: list[dict] = []
        for height in range(self._last + 1, tip + 1):
            _, scored = self.monitor.poll_block(height)
            invested = 0
            for s in sorted(self.monitor.suspicious(scored), key=lambda x: x.score.total, reverse=True):
                if s.tx.txid in self._seen:
                    continue
                self._seen.add(s.tx.txid)
                do_trace = self.auto_trace and invested < self.max_investigations
                if do_trace:
                    invested += 1
                event = self._event(height, s, do_trace)
                self.notifier.alert(event)
                raised.append(event)
            self._last = height
            self._save_state()
        return raised

    def run(self, max_polls: int | None = None) -> None:
        log.info(
            "monitor daemon started on %s (poll every %ds, auto_trace=%s)",
            self.monitor.provider.asset_info.symbol, self.poll_interval, self.auto_trace,
        )
        polls = 0
        failures = 0
        while max_polls is None or polls < max_polls:
            try:
                raised = self.poll_once()
                failures = 0
                if raised:
                    log.info("poll raised %d alert(s)", len(raised))
            except Exception as exc:  # noqa: BLE001 — a transient chain/network error must not kill the daemon
                failures += 1
                log.error("poll failed (%d consecutive): %s", failures, exc)
            polls += 1
            if max_polls is not None and polls >= max_polls:
                break
            # Brief exponential backoff after repeated failures (capped), so a chain
            # outage doesn't hammer the endpoint; normal cadence otherwise.
            delay = self.poll_interval * min(2 ** failures, 10) if failures else self.poll_interval
            time.sleep(delay)
