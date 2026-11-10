"""The sample generator, kept encrypted.

``make_samples.py`` writes realistic maldoc *structures* (VBA droppers, beacon
configs, obfuscated scripts — all inert), so antivirus engines flag the source
itself. It ships as ``scripts/make_samples.zip``, encrypted with the usual
password ``infected``, and is loaded **in memory** from there: no plain copy
touches the disk unless you ask for one to edit.

    python scripts/samplegen.py              # regenerate samples/samples.zip
    python scripts/samplegen.py --extract    # unpack samples.zip into samples/
    python scripts/samplegen.py --loose      # regenerate and also unpack
    python scripts/samplegen.py --unpack     # write scripts/make_samples.py to edit it (git-ignored)
    python scripts/samplegen.py --pack       # encrypt the edited make_samples.py back into the zip

From code (tests, other scripts): ``import samplegen; ms = samplegen.load()``;
afterwards ``import make_samples`` also works (the module is registered).
A plain ``scripts/make_samples.py`` (your edited copy), when present, wins.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLAIN = HERE / "make_samples.py"
PACKED = HERE / "make_samples.zip"
MEMBER = "make_samples.py"


def source() -> str:
    if PLAIN.is_file():
        return PLAIN.read_text(encoding="utf-8")
    sys.path.insert(0, str(HERE))
    import zipcrypto
    return zipcrypto.read(PACKED, MEMBER).decode("utf-8")


def load() -> types.ModuleType:
    """The generator as the module ``make_samples`` (compiled from memory)."""
    mod = sys.modules.get("make_samples")
    if mod is not None:
        return mod
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    mod = types.ModuleType("make_samples")
    mod.__file__ = str(PLAIN)                 # its paths (ROOT, samples/, scripts/) resolve as before
    sys.modules["make_samples"] = mod
    try:
        exec(compile(source(), str(PLAIN), "exec"), mod.__dict__)  # noqa: S102  (our own encrypted source)
    except BaseException:
        sys.modules.pop("make_samples", None)
        raise
    return mod


def pack() -> None:
    sys.path.insert(0, str(HERE))
    import zipcrypto
    zipcrypto.write(PACKED, {MEMBER: PLAIN.read_bytes()})
    print(f"Encrypted {PLAIN.name} into {PACKED.name} (password: infected). "
          f"Delete {PLAIN.name} if your antivirus flags it.")


def unpack() -> None:
    PLAIN.write_text(source(), encoding="utf-8")
    print(f"Wrote {PLAIN} (git-ignored). Edit it, then: python scripts/samplegen.py --pack")


if __name__ == "__main__":
    if "--pack" in sys.argv:
        pack()
    elif "--unpack" in sys.argv:
        unpack()
    else:
        load().main()
