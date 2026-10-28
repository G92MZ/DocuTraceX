"""Drop-in for the one piece of scikit-learn EMBER uses: ``FeatureHasher``.

scikit-learn (and scipy behind it, ~190 MB together) were needed only for the
hashing trick in the EMBER v3 features. This reproduces
``sklearn.feature_extraction.FeatureHasher(...).transform([x]).toarray()``
exactly — same MurmurHash3 (``mmh3``, x86 32-bit, seed 0, signed), same
``abs(h) % n`` bucket (and its ``-2**31`` special case), same alternate sign,
same ``"name=value"`` rewrite of string values, zero values skipped, float64
accumulation — so the vectors, and therefore the scores, are unchanged.
Equality with scikit-learn is checked in tests/test_ml.py."""

from __future__ import annotations

from typing import Any, Iterable

import mmh3
import numpy as np


def _index(h: int, n: int) -> int:
    if h == -2147483648:
        return (2147483647 - (n - 1)) % n
    return abs(h) % n


class _Row:
    def __init__(self, arr: np.ndarray) -> None:
        self._arr = arr

    def toarray(self) -> np.ndarray:
        return self._arr


class FeatureHasher:
    def __init__(self, n_features: int, input_type: str = "dict", alternate_sign: bool = True) -> None:
        self.n_features = n_features
        self.input_type = input_type
        self.alternate_sign = alternate_sign

    def transform(self, raw_X: Iterable[Any]) -> _Row:
        rows = []
        for x in raw_X:
            if isinstance(x, str):
                raise ValueError("Samples can not be a single string.")
            if self.input_type == "string":
                pairs = ((f, 1) for f in x)
            elif self.input_type == "dict":
                pairs = iter(x.items())
            else:
                pairs = iter(x)
            row = np.zeros(self.n_features, dtype=np.float64)
            for f, v in pairs:
                if isinstance(v, str):
                    f = f"{f}={v}"
                    value = 1.0
                else:
                    value = float(v)
                if value == 0:
                    continue
                if isinstance(f, str):
                    f = f.encode("utf-8")
                elif not isinstance(f, bytes):
                    raise TypeError("feature names must be strings")
                h = mmh3.hash(f, 0, signed=True)
                if self.alternate_sign and h < 0:
                    value = -value
                row[_index(h, self.n_features)] += value
            rows.append(row)
        return _Row(np.vstack(rows))
