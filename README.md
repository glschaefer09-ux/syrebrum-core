# Syrebrum Core

A small, local job runner that **refuses to run any effect (a write, command
or send) unless a policy engine says yes.** Core's own bookkeeping, its job
database, is the only thing it writes without asking. Python standard library
only, no runtime dependencies, nothing leaves your machine by default.

Status: v0.1.0 (first release). Apache-2.0. Maintained by
[CCD Enterprise & Development LLC](https://www.syrebrum.com/core/).

## What it does (and what the tests prove)

| Promise | Proven by |
|---|---|
| Effects (writes, commands, sends) are **denied** when no FailStop engine is configured | `tests/test_worker.py`, `tests/test_failstop.py` |
| A missing, slow, silent, malformed (including invalid Unicode or deep nesting), incomplete, wrong-version, or wrong-request answer is **denied** | `tests/test_failstop.py`, `test_malformed_allow_never_runs_handler` |
| An allow is bound to one exact request by a SHA-256 hash; it can't be reused for another | `test_hash_binds_every_field`, `test_socket_engine_cannot_forge_hash_for_other_request` |
| The policy socket is local only (Unix socket or loopback TCP) | `test_bad_addresses_rejected` |
| An effect handler gets exactly the target and args that were approved, and doesn't start if the job was cancelled or its lease lost before the final pre-effect check | `tests/test_worker.py`, `test_cancel_during_policy_wait_stops_effect` |
| Each approval is recorded in a receipt before the effect starts (proof of approval, not of execution) | `test_approval_recorded_before_effect_even_if_handler_fails` |
| Jobs are leased; a crashed worker's job is retried after its lease expires; a worker whose lease was taken over can't finish it | `tests/test_jobs.py` |
| Parallel threads and processes never hold a current lease on the same job | `test_concurrent_threads_never_double_claim`, `test_concurrent_processes_never_double_claim` |
| Every state change writes a hash-chained receipt; `verify` checks the chain and each job's kind, payload, result and state against its receipts; a saved head detects removed history up to that point | `test_tampering_detected`, `test_verify_detects_payload_and_result_edits`, `test_verify_detects_kind_change_and_removed_job`, `test_head_detects_truncation` |
| The local model adapter talks only to loopback addresses (127.0.0.1, ::1, localhost) unless you opt in, ignores proxies, never follows redirects, and has a call budget | `tests/test_providers_cli.py` |
| The inventory is read-only, runs no programs, makes no network calls and replaces the host name with a pseudonymous hash | `test_inventory_runs_no_programs_and_no_network` |

240 tests, offline (they use loopback sockets), Python 3.10 to 3.14. CI runs
Linux on 3.10 to 3.14 and Windows and macOS on 3.13.

## Install

```
pip install git+https://github.com/glschaefer09-ux/syrebrum-core@v0.1.0
```

## Use

```
syrebrum-core submit core.inventory
syrebrum-core work
syrebrum-core list
syrebrum-core verify
syrebrum-core check fs.write /etc/hosts
```

Exit codes: 0 ok, 2 bad input or unusable database, 3 denied, 4 verification failed.
`list`, `receipts` and `verify` open the database read-only.

`check` exits with code 3 (denied) until you point it at a FailStop engine
with `--failstop unix:/path/to.sock` or `SYREBRUM_FAILSTOP`. Data lives in
`~/.syrebrum/core.db` (override with `SYREBRUM_HOME` or `--db`).

Save the `head` value printed by `verify`. Later, run
`syrebrum-core verify --expect-head <value>` to detect if anyone deleted
recent history.

### In Python

```python
from syrebrum_core.jobs import JobBoard
from syrebrum_core.contracts import Task
from syrebrum_core.worker import Worker

board = JobBoard("jobs.db")
board.submit(Task("core.echo", {"hello": "world"}, idempotency_key="first"))

w = Worker(board, "my-worker")          # no FailStop => effects disabled
def my_writer(target: str, args: dict) -> dict:   # gets exactly what FailStop approved
    ...
    return {"written": target}

w.register("files.write", my_writer, effect=True, tool="fs.write")
w.run()
```

## Documents

- [docs/SPEC.md](docs/SPEC.md): the FailStop protocol v1, so anyone can build a compatible engine
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what Core defends against and what it doesn't
- [docs/DATA.md](docs/DATA.md): what is stored and what is sent (nothing, by default)
- [docs/PROVENANCE.md](docs/PROVENANCE.md): where the code came from and how it's licensed
- [docs/REVIEW-v0.1.md](docs/REVIEW-v0.1.md): independent review and scan results
- [SECURITY.md](SECURITY.md), [SUPPORT.md](SUPPORT.md), [CONTRIBUTING.md](CONTRIBUTING.md)

## Roadmap (not in v0.1)

These are plans, not features. Nothing below exists yet:
multi-machine workers over an authenticated channel, more local model adapters,
signed receipts, and a reference FailStop engine.

## License

Apache-2.0, copyright 2026 CCD Enterprise & Development LLC. See
[LICENSE](LICENSE) and [NOTICE](NOTICE). The license doesn't cover the Syrebrum
or FailStop names; see [TRADEMARKS.md](TRADEMARKS.md). Commercial products are
described in [COMMERCIAL.md](COMMERCIAL.md).
