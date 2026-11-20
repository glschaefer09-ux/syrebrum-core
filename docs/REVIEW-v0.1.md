# Security review: Syrebrum Core v0.1.0

This is the record of how v0.1.0 was checked before release: who reviewed it,
what they found and what changed. Findings are listed even when they were
fixed, so you can judge the process yourself.

## Method

- **Independent code review.** Rounds 1 to 3 were done by one AI security
  reviewer, separate from the agent that wrote the fixes. It had read-only
  access to the source, wrote small throwaway harnesses to confirm findings
  and couldn't change the code. Each round's fixes went back for re-review.
  Round 4 added three more independent reviewers on different AI models
  (Google Gemini, xAI Grok and Anthropic Claude), plus a repeated
  multi-process stress run that found finding 26.
- **Automated scans** that match what services like Aikido Security run:
  static analysis (SAST), secret detection, dependency (SCA) and license
  checks, and CI workflow checks. Results are in the table below.
- **Tests.** Code fixes come with regression tests (documentation and
  release-process fixes are checked by the release checklist). The 240 tests
  run offline and passed locally on Python 3.10 to 3.14 on Linux. The CI
  workflow also covers Windows and macOS; see "CI status" below.

## Findings and fixes

| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| 1 | High | An effect handler received the full job payload, not only what FailStop approved | Effect payloads must be exactly `{target, args}`; the handler receives a private copy of the approved request | `test_effect_extra_fields_denied` |
| 2 | High | The FailStop timeout was checked only between reads, so a slow reply could be accepted late | One absolute deadline covers connect, send and every read | `tests/test_failstop.py` |
| 3 | High | A Python adapter could change the request in place, or return a malformed or expired ALLOW | The request is snapshotted and hashed before the call; decisions are type-checked and expiry is checked after the call and again before dispatch | `tests/test_failstop.py`, `tests/test_worker.py` |
| 4 | High | The private planning documents and their history would have been published with the repository | The public repository is a fresh export with one commit; planning documents stay private | release checklist |
| 5 | Medium | The reply parser accepted missing `policy_version`, unknown or duplicate keys and NaN | Exact six-field schema; duplicates, NaN and Infinity rejected; depth and size bounded | `tests/test_failstop.py` |
| 6 | Medium | The local-model URL check could be bypassed with `LOCALHOST`, `;params` or empty `?` | The URL is rebuilt from validated parts; host normalized; user info, params, query and fragment rejected; proxies ignored | `tests/test_providers_cli.py` |
| 7 | Medium | A failed `BEGIN` left the board's lock held; a failed `COMMIT` wasn't rolled back | Lock released on any failure; rollback on commit failure; reads use a consistent snapshot | `tests/test_jobs.py` |
| 8 | Medium | The database could be created readable by other users in an existing folder; lease tokens were returned by `get` and `list` | Database and WAL files created 0600; symlinks and other users' files refused; tokens only returned to the claimer | `test_db_file_is_private`, `test_claimed_token_not_exposed_by_reads` |
| 9 | Medium | `verify` checked only the receipt chain; an edited job payload or result passed | `verify` reconciles every job's payload and result hash with its receipts and checks the saved head in one snapshot | `test_verify_detects_payload_and_result_edits` |
| 10 | Medium | `verify` on a mistyped path created an empty database and passed | Read-only commands open the database read-only and fail if it's missing | `test_cli_verify_missing_db_fails` |
| 11 | Low | Identifier regex used `$`, which accepts a trailing newline | `fullmatch` | `tests/test_contracts.py` |
| 12 | Low | Non-string JSON keys and tuples could make two different payloads share a hash | Plain-JSON validation before hashing; payloads are serialized once | `tests/test_contracts.py` |
| 13 | Low | Model adapter errors (truncated or deeply nested replies) escaped as raw exceptions; the call budget wasn't thread-safe | Wrapped as `ProviderError`; budget guarded by a lock | `tests/test_providers_cli.py` |
| 14 | Low | Inventory used `platform` functions that can start a subprocess | Uses `os.uname` and Windows version APIs only | `test_inventory_runs_no_programs_and_no_network` |
| 15 | Low | `setuptools>=69` didn't guarantee the license metadata format; no build or Windows job in CI | `setuptools>=78.1`; CI builds the wheel and source archive, installs it in a clean environment and runs on Windows and macOS | `.github/workflows/ci.yml` |
| 16 | Low | SBOM listed `pip` and a local build path | SBOM regenerated from `pyproject.toml` by `scripts/sbom.py` | `docs/sbom/` |
| 17 | Docs | Threat model overstated what the request hash and receipts prove | Rewritten: the hash isn't authentication, delivery is at-least-once, handlers aren't sandboxed | `docs/THREAT_MODEL.md` |
| 18 | High | A lone UTF-16 surrogate in `reason`, `approval_id` or `policy_version` passed validation, then made recording the result fail after the effect ran, so the job was retried and the effect ran twice; an in-process adapter could also return an empty `policy_version` | One validator for wire and in-process decisions rejects invalid Unicode and empty versions; the approval is recorded before the effect | `test_lone_surrogate_in_exact_allow_denies`, `test_malformed_allow_never_runs_handler` |
| 19 | Medium | A deeply nested model-server reply crashed the Python 3.14 interpreter (segfault) instead of raising an error | Nesting depth is checked with a small scanner before JSON parsing, for model and policy replies | `test_deeply_nested_reply_denied_without_parsing`, `test_deeply_nested_reply_rejected` |
| 20 | Medium | `allow_remote="false"` (a non-empty string) counted as opting in to a remote model server | `allow_remote` must be the boolean `True`; port 0 rejected | `test_allow_remote_must_be_bool` |
| 21 | Medium | Private database permissions depended on the parent folder; WAL/SHM side files could be symlinks | Parent folder must be yours or root's and not writable by others (unless sticky); the database and its side files are opened without following symlinks and checked after opening; limits documented | `test_folder_writable_by_others_refused`, `test_sidecar_symlink_refused` |
| 22 | Low | An ALLOW was recorded only when the effect succeeded | `effect_authorized` receipt written under the lease before the effect starts | `test_approval_recorded_before_effect_even_if_handler_fails` |
| 23 | Low | `verify` didn't check job kind or detect a removed job | Kind reconciled; jobs with receipts but no row are reported; scope (no state or attempt checks) documented | `test_verify_detects_kind_change_and_removed_job` |
| 24 | Low | Read-only commands created the default state folder; a huge job ID raised an overflow error; mutating a task after creation bypassed the payload size cap; approved args were read after the last expiry check | Read-only commands create nothing; job IDs range-checked; the cap is re-checked on the serialized payload; args are captured before the final check | `tests/test_jobs.py`, `tests/test_providers_cli.py`, `tests/test_worker.py` |
| 25 | Docs | README, review record and CI overstated some guarantees (exit code checked as any non-zero, chained license checks) | Wording narrowed; CI checks the exact exit code, each license file and the wheel's license metadata | `.github/workflows/ci.yml` |
| 26 | High | Round 3's permission fix opened and closed extra file descriptors on the database and its side files after connecting, which drops the process's SQLite locks; under multi-process load a worker crashed (SIGBUS) and the database could be corrupted | Files are checked with `lstat` before connecting and never opened separately; a new database is created 0600 with `O_EXCL` and SQLite copies that mode to its side files | `test_opening_second_board_keeps_first_boards_locks`, `test_concurrent_processes_never_double_claim` (40 repeated runs clean) |
| 27 | Medium | An in-process policy adapter could rewrite the request object it was given (through `__dict__`) so a different target or args ran, or an expired request was allowed | The adapter gets its own copy; the worker dispatches the target, args and expiry it captured before asking | `test_adapter_mutating_request_cannot_change_what_runs`, `test_adapter_cannot_extend_expiry_of_expired_request` |
| 28 | Medium | Editing a finished or cancelled job's state back to `queued`, or to `leased` with an expired lease, in the database passed `verify` and let a worker run it again | `claim` and lease expiry act only on jobs whose receipts agree with the row; `verify` checks every receipt follows a legal earlier event and each job's state matches its last receipt; a last-attempt lease expiry is now a `failed` receipt | `test_finished_job_edited_back_to_queued_is_not_run`, `test_finished_effect_edited_to_expired_lease_is_not_rerun`, `test_verify_rejects_impossible_event_order`, `test_job_inserted_outside_core_is_not_run` |
| 29 | Medium | Read-only opens (`list`, `receipts`, `verify`) skipped the folder and file checks, and sticky shared folders like `/tmp` let other users create SQLite's side files first | Every open runs the checks; any folder writable by others is refused, sticky or not; files readable by others are refused | `test_folder_writable_by_others_refused`, `test_readonly_refuses_sidecar_symlink`, `test_existing_db_readable_by_others_refused` |
| 30 | Medium | The nesting check could be bypassed with a non-UTF-8 model reply, because `json.loads(bytes)` also reads UTF-16 | Replies are strictly decoded as UTF-8 first, and the check runs on the exact text that is parsed; the check refuses bytes | `test_utf16_reply_cannot_hide_nesting` |
| 31 | Low | `verify` raised an exception (instead of reporting failure) on hand-edited values such as BLOBs or non-object JSON | Any unexpected value is reported as an altered database (exit 4) | `test_verify_reports_hand_edited_values_instead_of_crashing` |
| 32 | Low | Address checks accepted IPv6 zone IDs, control characters, backslashes and an empty Unix socket path | All rejected | `test_ollama_url_rejects_zone_ids_and_control_chars`, `test_failstop_address_rejects_odd_forms` |
| 33 | Low | An effect whose result couldn't be stored was retried (running the effect again); an over-long target was retried instead of denied | Once an effect has run, any failure to record it (bad result, database error) fails the job for good; invalid request: denied, never retried | `test_effect_with_unrecordable_result_is_not_rerun`, `test_effect_not_rerun_when_recording_fails`, `test_overlong_target_denied_not_retried` |
| 34 | Low | `submit --payload` accepted duplicate keys, NaN and deep nesting; `~/.syrebrum` permissions were changed through a symlink; a doc named a nonexistent `show` command | Strict JSON parser for CLI input; symlinked folder left alone; docs fixed | `test_cli_submit_rejects_loose_json` |
| 35 | Low | `authorize` could be called twice under one lease, writing a receipt chain that `verify` then rejected | A second authorize under the same lease is refused | `test_authorize_twice_under_one_lease_is_refused` |

## Scan results (release commit)

Scans were re-run on 2026-11-20 against the tree tagged `v0.1.0`, the exact tree that
was published. CI pins the same Ruff, Bandit, REUSE and pip-audit versions in
`.github/workflows/ci.yml`.

| Check | Tool | Result |
|---|---|---|
| Static analysis | Semgrep 1.186.0 rule packs: default, OWASP Top 10, security-audit, python, secrets, command-injection, sql-injection, insecure-transport, supply-chain, github-actions | 0 findings |
| Python security lint | Bandit 1.9.4 | 0 findings |
| Lint | Ruff 0.17.6 (incl. flake8-bandit and bugbear rules) | 0 findings |
| Secrets | Gitleaks 8.21.2 (files and git history of the public export) | 0 leaks |
| Dependencies | pip-audit 2.10.1 | no known vulnerabilities; Core has no runtime dependencies |
| Licensing | REUSE 6.3.0 | compliant; every file has a copyright and Apache-2.0 notice |
| CI workflow | zizmor 1.32.0 | 0 findings; actions pinned by commit SHA, read-only token, no persisted credentials |

## CI status

The full test suite (240 tests) and every check above passed locally on
Python 3.10, 3.11, 3.12, 3.13 and 3.14, and in GitHub Actions on Linux
(3.10 to 3.14), macOS and Windows for the release commit, including a build
and install of the package in a clean environment.

## Limits of this review

AI reviewers and scanners find many problems but not all of them. Read
[THREAT_MODEL.md](THREAT_MODEL.md) for what Core doesn't defend against.
Report anything we missed privately as described in
[SECURITY.md](../SECURITY.md).
