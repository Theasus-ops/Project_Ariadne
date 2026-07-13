"""Tests for the v1.0 deployment-readiness behaviour.

Covers the new operational contract: structured logging config, the CLI's
top-level error handling / exit codes / --version, and the production-WSGI
selection with a dev-server fallback. All offline.
"""

import logging

import pytest
from rich.console import Console

from ariadne import __version__, cli
from ariadne.cli import _run_wsgi, main
from ariadne.logging_setup import ROOT, configure, get_logger


# --------------------------------------------------------------------------- #
# logging_setup
# --------------------------------------------------------------------------- #
def test_configure_is_idempotent_no_duplicate_handlers():
    configure("INFO")
    first = len(logging.getLogger(ROOT).handlers)
    configure("INFO")
    second = len(logging.getLogger(ROOT).handlers)
    assert first == second == 1  # a single stderr handler, not stacked


def test_configure_sets_level_and_rejects_garbage():
    configure("DEBUG")
    assert logging.getLogger(ROOT).level == logging.DEBUG
    configure("not-a-level")  # falls back to WARNING, does not raise
    assert logging.getLogger(ROOT).level == logging.WARNING


def test_configure_writes_to_file(tmp_path):
    log_file = tmp_path / "logs" / "ariadne.log"  # parent does not exist yet
    configure("INFO", log_file=log_file)
    get_logger("test").info("hello-file-sink")
    for h in logging.getLogger(ROOT).handlers:
        h.flush()
    assert log_file.exists()
    assert "hello-file-sink" in log_file.read_text(encoding="utf-8")
    # reset so a file handler doesn't linger for later tests
    configure("WARNING")


def test_get_logger_namespacing():
    assert get_logger("daemon").name == "ariadne.daemon"
    assert get_logger("ariadne.cli").name == "ariadne.cli"  # already-qualified untouched


# --------------------------------------------------------------------------- #
# CLI entry point — --version, exit codes, error handling
# --------------------------------------------------------------------------- #
def test_version_flag_prints_and_exits_zero(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--version"])
    assert ei.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_user_error_returns_exit_2(tmp_path, capsys):
    # A missing wallets file is an expected, user-facing failure -> exit 2.
    code = main(["operation", "--name", "x", "--wallets", str(tmp_path / "nope.txt")])
    assert code == 2
    assert "Error:" in capsys.readouterr().out


def test_bad_address_returns_exit_2(capsys):
    code = main(["trace", "--chain", "btc", "definitely-not-an-address"])
    assert code == 2
    assert "Invalid btc address" in capsys.readouterr().out


def test_unexpected_error_returns_exit_1_clean(monkeypatch, capsys):
    def boom(args, console):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(cli, "cmd_config", boom)
    code = main(["config"])
    assert code == 1
    out = capsys.readouterr().out
    assert "provider exploded" in out
    assert "--debug" in out  # points the operator at the traceback, doesn't dump it


def test_unexpected_error_with_debug_reraises(monkeypatch):
    def boom(args, console):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(cli, "cmd_config", boom)
    with pytest.raises(RuntimeError):
        main(["--debug", "config"])


def test_keyboard_interrupt_returns_130(monkeypatch, capsys):
    def interrupt(args, console):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_config", interrupt)
    code = main(["config"])
    assert code == 130
    assert "Interrupted" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# production WSGI selection
# --------------------------------------------------------------------------- #
class _FakeApp:
    def __init__(self):
        self.ran = None

    def run(self, host, port, debug):
        self.ran = (host, port, debug)


def test_run_wsgi_dev_server_when_forced():
    app = _FakeApp()
    _run_wsgi(app, "127.0.0.1", 8000, prefer_dev=True, console=Console())
    assert app.ran == ("127.0.0.1", 8000, False)


def test_run_wsgi_falls_back_when_waitress_absent(capsys):
    # waitress is not a test dependency, so the import fails and we fall back to
    # the dev server with a visible note — never silently.
    app = _FakeApp()
    _run_wsgi(app, "0.0.0.0", 9000, prefer_dev=False, console=Console())
    assert app.ran == ("0.0.0.0", 9000, False)
    assert "waitress" in capsys.readouterr().out.lower()
