"""A value a script computes, with where it came from: its recipe.

Every evaluator works on :class:`Value` s. A literal starts a recipe (``here-string $P``,
``literal line 12``); each operation adds a step (``base64``, ``aes-256-cbc(key $K, iv $V)``,
``gzip``). The stage that reaches an "execute" / "load" / "write" call carries the whole recipe
to Nested, so the analyst sees how it was obtained.

Kinds: ``str``, ``bytes``, ``int``, ``float``, ``bool``, ``list``, ``dict``, ``null``, ``obj`` (an
object of the language: a stream, a cipher, a type — ``v`` holds its state) and ``unknown``
(not computable from the script: it depends on the machine, the network or input). An unknown
value flows through every operation as unknown, with the reason, so one gap does not stop the
rest of the script.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MAX_RECIPE = 40


@dataclass
class Value:
    kind: str
    v: Any = None
    recipe: tuple[str, ...] = ()
    why: str = ""                       # for unknown: what it depends on
    meta: dict[str, Any] = field(default_factory=dict)

    # -- constructors -----------------------------------------------------------------
    @staticmethod
    def of(v: Any, origin: str = "") -> "Value":
        """A value from a Python one (a literal of the script)."""
        rec = (origin,) if origin else ()
        if isinstance(v, Value):
            return v
        if v is None:
            return Value("null", None, rec)
        if isinstance(v, bool):
            return Value("bool", v, rec)
        if isinstance(v, int):
            return Value("int", v, rec)
        if isinstance(v, float):
            return Value("float", v, rec)
        if isinstance(v, str):
            return Value("str", v, rec)
        if isinstance(v, (bytes, bytearray)):
            return Value("bytes", bytes(v), rec)
        if isinstance(v, (list, tuple)):
            return Value("list", [Value.of(x) for x in v], rec)
        if isinstance(v, dict):
            return Value("dict", dict(v), rec)
        return Value("obj", v, rec)

    @staticmethod
    def unknown(why: str, recipe: tuple[str, ...] = ()) -> "Value":
        return Value("unknown", None, recipe, why=why)

    # -- recipe -----------------------------------------------------------------------
    def then(self, step: str, v: Any, kind: str | None = None) -> "Value":
        """The result of applying ``step`` to this value."""
        out = Value.of(v) if kind is None else Value(kind, v)
        rec = self.recipe + ((step,) if step else ())
        out.recipe = rec[-MAX_RECIPE:]
        return out

    def named(self, origin: str) -> "Value":
        """The same value, its recipe starting at ``origin`` when it has none yet."""
        if not self.recipe and origin:
            self.recipe = (origin,)
        return self

    @property
    def known(self) -> bool:
        return self.kind != "unknown"

    # -- coercions (as the languages do them) ----------------------------------------------
    def as_str(self) -> str | None:
        if self.kind == "str":
            return self.v
        if self.kind in ("int", "float"):
            return str(self.v)
        if self.kind == "bool":
            return "True" if self.v else "False"
        if self.kind == "null":
            return ""
        if self.kind == "list":
            parts = [x.as_str() for x in self.v]
            return None if any(p is None for p in parts) else " ".join(parts)
        if self.kind == "bytes":
            return self.v.decode("latin-1")
        return None

    def as_bytes(self) -> bytes | None:
        if self.kind == "bytes":
            return self.v
        if self.kind == "str":
            return self.v.encode("utf-8", "replace")
        if self.kind == "list":
            out = bytearray()
            for x in self.v:
                if x.kind == "int":
                    out.append(x.v & 0xFF)
                elif x.kind == "str" and len(x.v) == 1:
                    out.append(ord(x.v) & 0xFF)
                else:
                    return None
            return bytes(out)
        if self.kind == "int":
            return bytes([self.v & 0xFF])
        return None

    def as_int(self) -> int | None:
        if self.kind == "int":
            return self.v
        if self.kind == "bool":
            return int(self.v)
        if self.kind == "float":
            return int(self.v)
        if self.kind == "str":
            t = self.v.strip()
            try:
                return int(t, 16) if t.lower().startswith("0x") else int(t)
            except ValueError:
                return None
        return None

    def truthy(self) -> bool | None:
        if self.kind == "unknown":
            return None
        if self.kind in ("str", "bytes", "list", "dict"):
            return len(self.v) > 0
        if self.kind == "null":
            return False
        if self.kind == "obj":
            return True
        return bool(self.v)

    def short(self, n: int = 80) -> str:
        """A short readable form (for recipes and the Resolution tab)."""
        if self.kind == "str":
            s = self.v
            return repr(s if len(s) <= n else s[:n] + "…")
        if self.kind == "bytes":
            b = self.v
            return f"{len(b)} bytes {b[:min(16, n // 3)].hex()}{'…' if len(b) > 16 else ''}"
        if self.kind == "list":
            return f"list of {len(self.v)}"
        if self.kind == "unknown":
            return f"<unknown: {self.why}>"
        return repr(self.v)[:n]
