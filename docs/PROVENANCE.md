# Code provenance (v0.1)

Every file in `src/` and `tests/` was written fresh for this repository in
November 2026. Each one carries an SPDX header naming CCD Enterprise &
Development LLC as copyright holder under Apache-2.0.

- No code was copied, translated or adapted from any other CCD repository.
  CCD's commercial products are separate, differently licensed and remain
  private.
- What Core v0.1 shares with private products is only the *interface idea*:
  a policy engine is asked before an effect, and the answer is allow, hold
  or deny. The FailStop wire protocol here was written fresh as an open
  specification (docs/SPEC.md) so others can build compatible engines.
- No third-party code is included. There are no runtime dependencies. Test
  and audit tools (pytest, ruff, bandit, semgrep, gitleaks, pip-audit,
  reuse) are not shipped.
- Authorship: CCD Enterprise & Development LLC, with AI
  coding assistance (Perplexity Computer). AI-assisted commits carry a
  `Co-authored-by` trailer.

How this is checked: `reuse lint` must pass (every file has a license and
copyright), and the release checklist requires a fresh search of the
private repositories for any distinctive identifiers that appear in Core.
