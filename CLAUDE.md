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
