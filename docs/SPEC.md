# FailStop protocol, version 1

A client (Syrebrum Core) asks an engine whether one effect may happen. The
engine answers allow, hold or deny. **Anything other than a valid, matching
allow is treated as deny.**

## Transport

- A Unix domain socket (`unix:/path`), or TCP on a loopback address
  (`tcp://127.0.0.1:PORT`, `tcp://[::1]:PORT`). Non-loopback addresses are
  refused by the client.
- One request per connection. UTF-8 JSON, one object, terminated by `\n`.
- The client waits at most 5 seconds by default and reads at most 16 KiB.

## Request

```json
{"v": "1", "type": "decide", "request_hash": "<hex>",
 "request": {"principal": "worker-1", "tool": "fs.write", "target": "/srv/out.txt",
             "args": {}, "idempotency_key": "job-7-attempt-1", "tenant": "local",
             "expires_at": 1795000000.0}}
```

`request_hash` is SHA-256 over the canonical JSON of `{"v": "1", ...request}`.
Canonical JSON: object keys sorted by Unicode code point, separators `,` and
`:` with no spaces, UTF-8 without `\u` escaping of non-ASCII characters,
NaN and Infinity forbidden, duplicate keys forbidden. Only JSON types are
allowed (object with string keys, array, string, integer, float, true, false,
null), nested at most 32 levels.

Numbers: use integers between -(2^53-1) and 2^53-1 in `args` for portable
hashes. Floats (such as `expires_at`) are written the way Python's `repr`
writes them (the shortest form that round-trips, e.g. `1795000000.0`). An
engine in another language should hash the request exactly as canonicalized
here, and a hash mismatch is always a deny, so formatting differences fail
safe.

Identifiers (`principal`, `tool`, `tenant`, `idempotency_key`) match
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`. `target` is 1-1024 characters. `args`
is a JSON object of at most 64 KiB.

## Response

```json
{"v": "1", "verdict": "allow", "reason": "policy p3 rule 12",
 "request_hash": "<same hex>", "policy_version": "p3", "approval_id": null}
```

The reply must contain **exactly** these six fields. `approval_id` may be
`null`; `policy_version` must be a non-empty string.

The client denies when: a field is missing, unknown or duplicated; the reply
is not strict UTF-8 JSON (NaN and Infinity are rejected); `v` isn't `"1"`;
`request_hash` differs; `verdict` isn't exactly `allow`, `hold` or `deny`;
`reason` or `policy_version` aren't strings; `approval_id` is neither null nor
a string; the reply is over 16 KiB; no reply arrives in time; or the verdict
is allow but `expires_at` has passed.

`hold` means "not now, waiting for a human". Core records it as DENIED and
doesn't run the effect. Submit a new job once it's approved.

## Canonical JSON test vectors

| Value | Canonical text | SHA-256 |
|---|---|---|
| `{}` | `{}` | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` |
| `{"b": 1, "a": [true, null, "x"]}` | `{"a":[true,null,"x"],"b":1}` | |
| `{"t": "é"}` | `{"t":"é"}` (raw UTF-8, not `\u00e9`) | |
| `{"f": 1.5, "i": 10}` | `{"f":1.5,"i":10}` | |

Object keys must be strings. Values are limited to JSON types, at most 32
levels deep, with no lone surrogates. Integers are written without a decimal
point; floats use the shortest round-trip form (Python `repr`). To avoid
cross-language float differences, prefer integers or strings in `args`.

## In-process adapters

Python code can implement `decide(request) -> Decision` directly. The answer
is validated exactly like a wire reply (types, hash, expiry). In-process
adapters run synchronously, so the client cannot time them out: use
`SocketFailStop` for an engine you don't fully trust.
