"""Per-object progress for analysis steps that walk every object of a case.

YARA, C2 and ML scan the original plus everything extracted, unpacked and
decrypted — a few seconds, or minutes on a large MSI or archive. ``ObjectProgress``
shows "object 4/12 · extracted/…/a.dll" live in the Tasks tab while the step runs
(through ``analyze.step_progress_reporter``) and keeps the objects worth seeing
afterwards: the slow ones and the ones with results. They go in the module's
``timings`` list, which the step runner moves into the step record
(``substeps``) — they are not part of the module result itself.

Reporting must never break an analysis: every call swallows its own errors.
"""

from __future__ import annotations

import time
from typing import Any

# Objects kept in the step record: the slowest ones, plus any with results.
MAX_KEPT = 25
# Below this, an object without results is not worth a row.
SLOW_S = 1.0


class ObjectProgress:
    def __init__(self, total: int | None = None, noun: str = "object") -> None:
        try:
            from .analyze import step_progress_reporter
            self._report = step_progress_reporter()
        except Exception:  # noqa: BLE001
            self._report = lambda _detail: None
        self.total = total
        self.noun = noun
        self.n = 0
        self._t: float | None = None
        self._cur: dict[str, Any] | None = None
        self.records: list[dict[str, Any]] = []

    def start(self, label: str, kind: str = "") -> None:
        """A new object: closes the previous one (no results) and shows this one."""
        if self._cur is not None:
            self.done()
        self.n += 1
        self._t = time.perf_counter()
        self._cur = {"name": label, "chain": label, "depth": 1, "kind": kind}
        pos = f"{self.noun} {self.n}/{self.total}" if self.total else f"{self.noun} {self.n}"
        where = label if len(label) <= 70 else "…" + label[-69:]
        try:
            self._report(f"{pos} · {where}")
        except Exception:  # noqa: BLE001
            pass

    def done(self, findings: int = 0, detail: str = "", status: str = "") -> None:
        """Close the current object with what it produced."""
        cur, self._cur = self._cur, None
        if cur is None or self._t is None:
            return
        try:
            cur["duration_s"] = round(time.perf_counter() - self._t, 2)
            cur["findings"] = int(findings)
            if detail:
                cur["detail"] = str(detail)[:200]
            cur["status"] = status or ("ok_with_findings" if findings else "ok")
            self.records.append(cur)
        except Exception:  # noqa: BLE001
            pass

    def timings(self) -> list[dict[str, Any]]:
        """Objects with results or slower than SLOW_S, slowest first (MAX_KEPT)."""
        if self._cur is not None:
            self.done()
        keep = [r for r in self.records
                if r.get("findings") or r.get("detail") or r.get("duration_s", 0) >= SLOW_S]
        keep.sort(key=lambda r: (not r.get("findings"), -r.get("duration_s", 0)))
        return keep[:MAX_KEPT]
