# Release checklist

Run for every release. Don't tag until every box is checked.

1. `scripts/check.sh` passes (tests, ruff, bandit, reuse, pip-audit).
2. Tests pass on Python 3.10, 3.11, 3.12 and 3.13; CI green on Linux, Windows and macOS.
3. Semgrep packs listed in REVIEW, gitleaks (files and history) and zizmor are clean.
4. `python scripts/sbom.py` output matches `docs/sbom/`.
5. `python -m build` succeeds; the wheel installs in a clean venv; after `submit core.echo` and `work` seed a database, `syrebrum-core verify` exits 0 and `check fs.write /tmp/x` exits 3.
6. The source archive contains LICENSE and NOTICE and no private documents.
7. Independent review re-run on the release commit; no open High or Medium findings.
8. README claims each map to a passing test; REVIEW is updated.
9. No private product names, paths, hosts, emails or tokens in any file.
10. Tag `vX.Y.Z`, create the GitHub release, and confirm private vulnerability reporting is on.
11. Within an hour: re-run the scans on the public repository and check every link on the website.
