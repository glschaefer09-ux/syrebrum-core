# What data Syrebrum Core stores and sends

**Sent anywhere: nothing by default.** Core has no telemetry, no update
checks and no analytics. It opens network connections only when you ask it
to:
- to a FailStop engine at the address you configure (local only), and
- to an Ollama model server you configure (127.0.0.1 unless you opt in).

**Stored:** one SQLite database, `~/.syrebrum/core.db`, plus SQLite's
`core.db-wal` and `core.db-shm` working files next to it. The folder is
created owner-only (0700) and the files owner-only (0600) on Linux and macOS.
On Windows they inherit your profile folder's permissions. Core refuses a
database in a folder other users can write to, such as `/tmp`; use a folder
only you can write to.

It holds, in plain text (not encrypted):
- job kinds, payloads and results, exactly as submitted and returned;
- receipts: event names, worker IDs you choose, error messages, and SHA-256
  hashes of payloads and results. Each approved effect gets an
  `effect_authorized` receipt with the policy decision, written before the
  effect starts (it proves approval, not that the effect ran);
- lease tokens for running jobs.

Read-only commands (`list`, `receipts`, `verify`) don't create the database or
its folder, but SQLite may create the `-wal` and `-shm` files when it opens an
existing database. `verify` checks the receipt chain and each job's kind,
payload, result and state against its receipts; it doesn't check attempt
counts, leases or timestamps.

Don't put secrets in payloads. To erase everything, stop all workers and
delete the three files. Deleting isn't a secure erase: the data may remain on
disk or in backups until overwritten.

**Inventory:** `core.inventory` reads OS name and version, CPU count, Python
version and disk sizes. The host name is replaced by a short hash unless you
pass `include_hostname`. It doesn't read files, users, processes or network
settings.
