"""Operator notifications for the monitoring daemon.

A notifier fans an alert out to wherever the operator watches: the console, a
persistent JSONL log, and/or an HTTP webhook (point it at Slack, Discord, a SIEM,
or PagerDuty). Every sink is best-effort -- a broken webhook never stops the
daemon or masks the other channels.
"""

from __future__ import annotations

import json
from pathlib import Path

import requests


class Notifier:
    def alert(self, event: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class ConsoleNotifier(Notifier):
    _STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}

    def __init__(self, console=None) -> None:
        self.console = console

    def alert(self, event: dict) -> None:
        level = event.get("level", "medium")
        line = (
            f"[ALERT · {level.upper()}] {event.get('chain')} tx {str(event.get('txid', ''))[:16]}.. "
            f"score {event.get('score')} — {'; '.join(event.get('reasons', [])[:2]) or 'flagged'}"
        )
        rec = event.get("recommended_action")
        if self.console is not None:
            style = self._STYLE.get(level, "yellow")
            self.console.print(f"\a[{style}]{line}[/]")
            if rec:
                self.console.print(f"        [dim]→ {rec}[/]")
            if event.get("report"):
                self.console.print(f"        [green]report:[/] {event['report']}")
        else:
            print("\a" + line)
            if rec:
                print("   -> " + rec)


class FileNotifier(Notifier):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def alert(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")


class WebhookNotifier(Notifier):
    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout

    def alert(self, event: dict) -> None:
        try:
            requests.post(self.url, json=event, timeout=self.timeout)
        except Exception:
            pass


class CompositeNotifier(Notifier):
    def __init__(self, notifiers) -> None:
        self.notifiers = list(notifiers)

    def alert(self, event: dict) -> None:
        for notifier in self.notifiers:
            try:
                notifier.alert(event)
            except Exception:
                pass
