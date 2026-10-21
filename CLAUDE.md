# DocuTraceX — notes for Claude

## Versioning

- Every change that will be merged (PR, push meant for `main`) must bump the
  version in `VERSION` (semver, no trailing newline). `update.py` compares the
  local `VERSION` with the one on GitHub, so without a bump users never get
  the update.

<!-- gmzpt -->

## Pull requests

- When a change is ready, push it and open the pull request directly (no need
  to ask first); the owner reviews it on GitHub.

## Samples (always keep them testable)

- Every change that adds or updates an analysis tool, parser, engine or
  detection capability must also add a new sample — or update an existing one —
  so the feature can be exercised end to end. Generators live in
  `scripts/make_samples.py`; document each sample in `samples/README.md`.
- Samples are **benign**: inert indicators only (`*.example`, RFC 5737 IPs,
  `MZ`+text stubs). They tell the same invoice-fraud story as the rest.
- Keep `samples/samples.zip` (password `infected`) in sync when samples change
  (`python scripts/make_samples.py`, or add entries to the existing archive).
