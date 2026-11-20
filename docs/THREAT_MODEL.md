# Threat model (v0.1)

## Assets
The machine Core runs on, the job database and its receipts, and anything an
effect handler could change.

## Defended

| Threat | Defence |
|---|---|
| A bug or malicious job tries an effect with no policy engine | NoFailStop denies all effects by default |
| Policy engine down, slow or crashed | Timeout and connection errors become deny |
| Stale or misdirected allow | Allow must echo the SHA-256 of this exact request, and it expires. The hash binds the answer to the request; it is not authentication (see below) |
| Malformed or oversized reply (parser abuse) | Strict parsing, 16 KiB cap; deny on any doubt |
| Remote policy engine or model host (data leaving the machine) | Loopback-only by default; remote model hosts need explicit opt-in |
| Redirect from the model host to another host | Redirects are never followed |
| Runaway model usage | Per-provider call budget, prompt and reply size caps |
| Two workers holding the same job at once | `BEGIN IMMEDIATE` transactions and lease tokens (an expired lease can be reclaimed; see at-least-once below) |
| A crashed worker leaves a job stuck | Leases expire and the job is retried up to `max_attempts` |
| Silent edits to history or job data | Hash-chained receipts; `verify` also checks each job's payload and result against its receipts; `verify --expect-head` detects truncation |
| SQL injection through job kinds | Identifiers validated; every query is a fixed string with bound parameters |
| Effect handler gets different input than was approved | Effect payloads are exactly `{target, args}`; the handler receives a copy of the frozen, hashed request |
| Job cancelled or lease lost while waiting for FailStop | After the decision, the approval is recorded under the lease (fails if the lease is gone) and expiry is re-checked, before the effect |
| Malformed allow (invalid Unicode, empty policy version, deep nesting) | One validator for wire replies and in-process adapters; nesting checked on the exact text that is parsed; deny on any failure |
| An in-process adapter changing the request it was asked about | The adapter gets its own copy; the worker dispatches the target and args it captured before asking |
| A finished or cancelled job edited back to `queued` or `leased` in the database | `claim` and lease expiry act only when the receipts agree with the row; `verify` checks the order of each job's receipts and its state |
| A handler whose effect ran but whose result can't be stored (not JSON, too large, database error) | The job fails for good instead of retrying, so the effect doesn't run twice (a crash or lost lease mid-effect is still retried: at-least-once) |
| Proxy settings sending prompts off the machine | The Ollama adapter ignores proxy environment variables, pins `localhost` to 127.0.0.1 and requires a real `True` to allow a remote host |
| Other users reading the job database | The database file is created owner-only (0600) on Linux/macOS; symlinks and other users' files are refused |

## Not defended (out of scope for v0.1)

- **Someone who already controls your user account or root.** They can
  rewrite the database and recompute the chain. Keep the head hash somewhere
  else (e.g. a printed note or a separate machine). Signed receipts are on
  the roadmap.
- **What an allowed handler does.** Core enforces the ask-first rule; your
  handler's own code must be safe, and should be idempotent, because a job
  that fails after an allow may be retried (with a new request and a new
  decision).
- **The policy engine's correctness.** Core trusts the engine's verdict.
- **A hard fence around the handler.** Recording the approval under the
  lease right before an effect narrows the cancel/expiry race to a short
  window but can't stop a handler that is already running. Cancelling a job doesn't undo an effect
  that has started.
- **Untrusted in-process adapters.** A Python FailStop adapter runs in the
  same process; its answer is validated, but it can't be timed out.
- **Local processes that can reach or impersonate the FailStop endpoint.**
  The request hash proves an answer is about this request, not who sent it.
  Authentication is the endpoint itself: use a Unix socket in a folder only
  your user and the engine can open. A loopback TCP port can be taken by any
  local process.
- **Exactly-once delivery.** Jobs are at-least-once: a job whose lease
  expires is retried, so handlers must be idempotent.
- **An OS sandbox for handlers.** Handlers run with your user's full
  permissions in the worker process.
- **Heartbeat limits.** A long FailStop wait or handler can outlive its
  lease; the fence check catches this before the effect starts, not during.
- Read-only handlers (`core.echo`, `core.inventory`) run without asking
  FailStop. Register anything that changes state with `effect=True`.

## Local file trust

Before every open, including read-only ones, Core refuses its database if
the folder holding it isn't owned by you (or root) or is writable by anyone
else. That includes shared folders such as `/tmp`, sticky bit or not, because
other users could create SQLite's side files there first. The database and its
`-wal`, `-shm` and `-journal` files must be regular files you own, not
symbolic links, and not readable or writable by other users. A new database is
created owner-only (0600) and SQLite gives its side files the same mode.

These checks use `lstat` and never open the files: opening and closing an
extra descriptor on a SQLite file would drop the process's locks on it. They
assume the folders above the database are trustworthy too; someone who
controls a parent folder can still swap paths between the check and the open.
On Windows these POSIX checks don't apply; the files rely on your profile
folder's ACLs.
