#!/usr/bin/env bash
# Runs every release check. Needs: pytest ruff bandit reuse pip-audit (dev only).
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
python -m pytest -q -p no:cacheprovider
ruff check --select E,F,W,B,S,UP,I --ignore S101,E501 src tests
bandit -q -r src
reuse lint
python -m pip_audit --strict --progress-spinner off .
echo "all checks passed"
