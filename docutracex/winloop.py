"""The asyncio event loop the web service runs on.

On Windows asyncio's default loop (Proactor) has a known bug (CPython gh-93821): a client
that resets its connection while it is being accepted (``WinError 64``, "the specified
network name is no longer available") makes the loop **close the listening socket**, so the
service stops answering until it is restarted. The Selector loop accepts the same way
without that bug; the service needs nothing only Proactor has (tools run with
``subprocess``, not asyncio subprocesses). Elsewhere uvicorn's default is kept.
"""

from __future__ import annotations

import asyncio
import os
import sys


def uvicorn_loop() -> str:
    """The ``loop`` argument for ``uvicorn.run``. ``DOCUTRACEX_EVENT_LOOP=proactor`` keeps
    the Proactor loop on Windows."""
    if sys.platform != "win32" or os.environ.get("DOCUTRACEX_EVENT_LOOP", "").lower() == "proactor":
        return "auto"
    try:
        from uvicorn.loops import asyncio as uv_asyncio
        factory = hasattr(uv_asyncio, "asyncio_loop_factory")
    except ImportError:
        factory = False
    if factory:                       # uvicorn >= 0.36: a loop factory (no policy, deprecated in 3.14)
        return "asyncio:SelectorEventLoop"
    import warnings
    with warnings.catch_warnings():   # older uvicorn sets up the loop through the policy
        warnings.simplefilter("ignore", DeprecationWarning)
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined]
    return "asyncio"
