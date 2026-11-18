# Vendored third-party code

| Package | Version | License | Why it is here |
| --- | --- | --- | --- |
| `autoit_ripper` | 1.2.0 (unmodified) | MIT (`autoit_ripper/LICENSE`) | Recovers the script of compiled AutoIt files (EXEs, `.a3x`, blobs with junk in front). Bundled so compiled AutoIt is always decompiled, also when the portable Python has no `autoit-ripper`; it runs in its own child process with a time limit (`run_autoit_ripper.py`). |
