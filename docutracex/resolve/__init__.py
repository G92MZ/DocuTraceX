"""Static resolution of scripts: follow a script's values and operations to what it runs,
loads or writes, without running it.

- ``transforms``: the operations every language shares (decodings, ciphers, compressions,
  string operations, hashes), pure and bounded — no disk, network or process;
- ``value``: a value with its recipe (the literal it came from and the operations applied);
- ``sinks``: what a script hands to an "execute", "load" or "write" call, downloads and the
  calls that could not be resolved — the stages that go to Nested;
- ``langdetect``: the language of a script by its content (a ``.txt``, a file without a telling
  extension), so only the engines that fit it read it.

Nothing here executes the script: values are computed from its text.
"""
