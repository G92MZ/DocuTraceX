"""Windows: the web service runs on asyncio's Selector loop (Proactor closes the listening
socket on WinError 64, CPython gh-93821); elsewhere uvicorn's default."""

from __future__ import annotations

import asyncio
import sys

import pytest

from docutracex import winloop


def test_default_loop_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert winloop.uvicorn_loop() == "auto"


def test_selector_loop_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """uvicorn >= 0.36: the Selector loop as a loop factory, the policy left alone."""
    from uvicorn.loops import asyncio as _uv  # noqa: F401  (imported before faking win32)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(asyncio, "set_event_loop_policy", lambda p: pytest.fail("policy changed"))
    loop = winloop.uvicorn_loop()
    assert loop == "asyncio:SelectorEventLoop"
    from uvicorn.config import Config
    assert Config("docutracex.app:app", loop=loop).get_loop_factory() is asyncio.SelectorEventLoop


def test_selector_policy_on_old_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Older uvicorn (no loop factory): through the event loop policy."""
    from uvicorn.loops import asyncio as uv_asyncio
    set_to: list[object] = []
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delattr(uv_asyncio, "asyncio_loop_factory")
    monkeypatch.setattr(asyncio, "WindowsSelectorEventLoopPolicy", lambda: "selector-policy", raising=False)
    monkeypatch.setattr(asyncio, "set_event_loop_policy", set_to.append)
    assert winloop.uvicorn_loop() == "asyncio"
    assert set_to == ["selector-policy"]


def test_proactor_kept_when_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("DOCUTRACEX_EVENT_LOOP", "proactor")
    monkeypatch.setattr(asyncio, "set_event_loop_policy", lambda p: pytest.fail("policy changed"))
    assert winloop.uvicorn_loop() == "auto"
