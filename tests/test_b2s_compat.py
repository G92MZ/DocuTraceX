"""The Python stand-in for binary2strings gives what the C++ module gives (FLOSS's Rust
strings depend on it). Expected values below were produced by binary2strings 0.1.13; with
the module installed, a larger randomised comparison runs too."""

from __future__ import annotations

import importlib.util
import random

import pytest

from docutracex import b2s_compat

GOLDEN = {
 "rust_blob": {
  "hex": "68747470733a2f2f66616374757261732d63646e2e6578616d706c652f676174652e7068704d6f7a696c6c612f352e30202857696e646f7773204e542031302e302970656469646f5f373733312e706466",
  "all4": [
   [
    "https://facturas-cdn.example/gate.phpMozilla/5.0 (Windows NT 10.0)pedido_7731.pdf",
    "UTF8",
    [
     0,
     80
    ]
   ]
  ],
  "all6": [
   [
    "https://facturas-cdn.example/gate.phpMozilla/5.0 (Windows NT 10.0)pedido_7731.pdf",
    "UTF8",
    [
     0,
     80
    ]
   ]
  ],
  "one": [
   [
    "https://facturas-cdn.example/gate.phpMozilla/5.0 (Windows NT 10.0)pedido_7731.pdf",
    "UTF8",
    [
     0,
     80
    ]
   ],
   [
    "ttps://facturas-cdn.example/gate.phpMozilla/5.0 (Windows NT 10.0)pedido_7731.pdf",
    "UTF8",
    [
     0,
     79
    ]
   ],
   [
    "tps://facturas-cdn.example/gate.phpMozilla/5.0 (Windows NT 10.0)pedido_7731.pdf",
    "UTF8",
    [
     0,
     78
    ]
   ],
   [
    "ps://facturas-cdn.example/gate.phpMozilla/5.0 (Windows NT 10.0)pedido_7731.pdf",
    "UTF8",
    [
     0,
     77
    ]
   ]
  ]
 },
 "mixed": {
  "hex": "00014d5a9000c3b1616e64c3ba20636166c3a900fffe1f044004380432043504420420003c0438044004000007e697a5e69cace8aa9ee38386e382ade382b9e38388006600610063007400750072006100000061620063646566000000",
  "all4": [
   [
    "ñandú café",
    "UTF8",
    [
     6,
     18
    ]
   ],
   [
    "Привет мир",
    "WIDE_STRING",
    [
     22,
     40
    ]
   ],
   [
    "日本語テキスト",
    "UTF8",
    [
     45,
     65
    ]
   ],
   [
    "factura",
    "WIDE_STRING",
    [
     67,
     79
    ]
   ],
   [
    "cdef",
    "UTF8",
    [
     86,
     89
    ]
   ]
  ],
  "all6": [
   [
    "ñandú café",
    "UTF8",
    [
     6,
     18
    ]
   ],
   [
    "Привет мир",
    "WIDE_STRING",
    [
     22,
     40
    ]
   ],
   [
    "日本語テキスト",
    "UTF8",
    [
     45,
     65
    ]
   ],
   [
    "factura",
    "WIDE_STRING",
    [
     67,
     79
    ]
   ]
  ],
  "one": [
   [
    "",
    "",
    [
     0,
     0
    ]
   ],
   [
    "",
    "",
    [
     0,
     0
    ]
   ],
   [
    "",
    "",
    [
     0,
     0
    ]
   ],
   [
    "",
    "",
    [
     0,
     0
    ]
   ]
  ]
 },
 "wide_after_nul": {
  "hex": "0070616e69636b65642061740000007841004200430044004500",
  "all4": [
   [
    "panicked at",
    "UTF8",
    [
     1,
     11
    ]
   ],
   [
    "ABCDE",
    "WIDE_STRING",
    [
     16,
     24
    ]
   ]
  ],
  "all6": [
   [
    "panicked at",
    "UTF8",
    [
     1,
     11
    ]
   ]
  ],
  "one": [
   [
    "",
    "",
    [
     0,
     0
    ]
   ],
   [
    "panicked at",
    "UTF8",
    [
     0,
     10
    ]
   ],
   [
    "anicked at",
    "UTF8",
    [
     0,
     9
    ]
   ],
   [
    "nicked at",
    "UTF8",
    [
     0,
     8
    ]
   ]
  ]
 }
}


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_same_as_binary2strings(name: str) -> None:
    g = GOLDEN[name]
    buf = bytes.fromhex(g["hex"])
    for mc, key in ((4, "all4"), (6, "all6")):
        got = [[s, t, list(p)] for s, t, p, _ in b2s_compat.extract_all_strings(buf, mc)]
        assert got == g[key]
    for i, want in zip((0, 1, 2, 3), g["one"]):
        s, t, p, _ = b2s_compat.extract_string(buf[i:])
        assert [s, t, list(p)] == want


def test_arguments() -> None:
    with pytest.raises(RuntimeError):
        b2s_compat.extract_all_strings(b"abcd", 0)
    assert b2s_compat.extract_string(b"\x00\x01") == ("", "", (0, 0), False)


@pytest.mark.skipif(importlib.util.find_spec("binary2strings") is None, reason="binary2strings not installed")
def test_randomised_against_the_module() -> None:
    import binary2strings
    rnd = random.Random(11)
    words = ["factura", "https://facturas-cdn.example/gate.php", "Привет мир", "日本語テキスト", "ñandú café"]
    for _ in range(40):
        b = bytearray()
        for _ in range(rnd.randint(5, 50)):
            r = rnd.random()
            w = rnd.choice(words)
            b += w.encode() if r < 0.5 else w.encode("utf-16le") if r < 0.75 else bytes(rnd.getrandbits(8) for _ in range(9))
        for mc in (4, 6):
            want = [(s, t, tuple(p)) for s, t, p, _ in binary2strings.extract_all_strings(bytes(b), mc)]
            got = [(s, t, tuple(p)) for s, t, p, _ in b2s_compat.extract_all_strings(bytes(b), mc)]
            assert got == want
