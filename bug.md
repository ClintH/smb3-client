# Improvements for `smb3-client`, from comparing it with `smb2` (Rust)

Measured 2026-11-09 against `//igloo.local/Temp` (SMB 3.1.1, 5–14 ms RTT, mean 7.8 ms), from macOS arm64, Node v26.3.1.
Client under test: `@clinth/smb3-client` 0.2.2 (the `ClintH/smb3-client` fork). I read the built `dist/` of that version and the
fork's `src/` layout; the fork's working tree has uncommitted changes (`package.json`, `src/connection/connection.ts`) that I did not
read, so check file and line references against your tree. Reference implementation: `smb2` crate 0.43.0 / CLI 0.7.3
(`vdavid/smb2`, MIT OR Apache-2.0), source read at `crates/smb2/src/client/`.

## Summary

Nothing here argues for a Rust binding. The one large gap is **request concurrency on reads**, and it is a JavaScript fix.

| 256 MiB download, same share                                     |             MiB/s |
| ---------------------------------------------------------------- | ----------------: |
| smb2 CLI (`smb2 get`)                                            | 47–53 (5.0–5.5 s) |
| macOS mount (`cp`)                                               |             42–44 |
| smb3-client, 1 request in flight (what blocktransfer does today) |             30–31 |
| smb3-client, 4 requests in flight, 1 MiB each                    |             46–49 |
| smb3-client, 8 requests in flight, 1 MiB each                    |             50–53 |

With 4–8 requests in flight the client reaches the same rate as smb2 and the link. Uploads are different: smb2, `cp` and
smb3-client all land at 7–9 MiB/s (256 MiB: smb2 29.8–33.2 s, `cp` 34.0–38.8 s; 64 MiB with smb3-client: 7.4 MiB/s at 1 request,
8.6 MiB/s at 8). That share's write speed is the limit, so **no client change was shown to help uploads**, and upload work should wait
for a server that writes faster.

## Evidence that encryption is not the cause

The first benchmark showed direct reads at 0.57× the mount (31.9 vs 55.6 MiB/s) and the direct session was encrypted
(`globalEncrypt: true`, cipher id 2) while the mount was not (`SMB_CURR_ENCRYPT_ALGORITHM OFF`). To separate the two, the same file was
read with `encryption: 'if-offered'` and `'disabled'`, one request at a time: 31.2 vs 31.3 MiB/s (a first, cold run of the
unencrypted case gave 16.8 MiB/s and should be ignored). Encryption costs nothing measurable at this link speed. It is untested at
gigabit rates, where JavaScript AES-GCM could become the limit.

## Findings, in priority order

### 1. `StorageHandle.read` issues one request at a time (high)

`src/open/read.ts` `readAt` loops `while (got < length) { await readOnce(...) }`. Each READ waits for the previous answer, so a
read costs one round trip per chunk. At 7.8 ms RTT and 1 MiB per request, one request in flight tops out near 31 MiB/s here, while
the link allows about 50. `readAll` and `readRange` pipeline (4 at a time, `READ_CONCURRENCY`), but `StorageHandle.read(position,
length)`, the call blocktransfer uses, does not.

Proposals:
- Make `readAt` split `[offset, offset + length)` into chunks and run them through `mapConcurrent`, as `writeAll` already does.
  That helps only when a caller asks for more than one chunk at once, so also:
- Offer a way to keep several reads in flight from one handle without the caller managing it: either `readMany(ranges)`, or a
  sequential read-ahead stream on a `StorageHandle`. `readStream.ts` already has the machinery (`concurrency`, default 4, max 8);
  expose it for storage handles.
- Document that `StorageHandle` calls are independent and may be issued concurrently, with a recommended depth of 4–8.

`smb2` does the equivalent in `client/read_ahead.rs`.

### 2. Writes only overlap within one call (medium)

`writeAll` pipelines 4 WRITEs, but a 1 MiB block with `MAX_IO_SIZE = 1 MiB` is a single request, so a caller writing blocks in
sequence has one WRITE in flight. This did not change upload speed on this share (7.4 → 8.6 MiB/s going from 1 to 8 concurrent writes),
so the priority is medium: worth doing for symmetry with reads, not worth measuring until a faster-writing server is available.
`smb2` keeps a push-based writer (`write_pipe.rs`) that accepts bytes and sends as the credit window allows.

### 3. Credit window starts at one request and asks for 64 (medium)

`connection.ts`: `TARGET_CREDITS = 64`; `maxIoSize` caps a request at `peakCredits × 64 KiB`, and `peakCredits` starts at 1. A new
connection therefore sends 64 KiB requests until grants grow. `smb2` asks the server for a 512-credit window on every request
(`CREDIT_TARGET` in `credits.rs`) and charges requests by `ceil(bytes / 64 KiB)`. Observed `peakCredits` was 64 with one request in
flight and 160 with four or more, so this server grants more than 64 when asked.

Proposals: raise `TARGET_CREDITS` (512 is what smb2 uses; servers clamp it, so asking high is safe), and consider raising `MAX_IO_SIZE`
above 1 MiB when the server's `maxReadSize` and `maxWriteSize` allow it (this share advertises 8 MiB). A 4 MiB request with four in
flight was not faster than 1 MiB (42.7 vs 48.9 MiB/s), so depth matters more than size here.

### 4. Fixed depth versus a window sized to the link (low)

`smb2` sizes its in-flight window from the measured rate times (RTT + a learned headroom), per direction, and caps it. Its source
explains why: before 0.25 it kept up to 32 WRITEs in flight, and a `stat` on the same connection waited behind all of them (23 s on
a 375 KB/s uplink). On this link a fixed depth of 8 already reaches the link rate, so a fixed depth is enough for now. Whatever
depth is chosen, bound the bytes in flight, because a deep queue delays everything else on the connection (listings, stat,
cancel).

### 5. Compound requests for small files (low to medium)

`smb2` combines CREATE+READ+CLOSE in one round trip, and also stat, rename and delete. smb3-client sends these separately. In the
storage-level benchmark direct small-file transfers were already faster than the mount (16 × 4 KiB uploads: 0.21 s direct, 0.79 s
mounted), so the gain would show up in directory trees of many small files rather than in the large-file numbers. Measure per-file
cost with a larger file count before building it.

### 6. Request timeout behaviour (low)

One direct upload failed with `SmbProtocolError: SMB request timed out` (`ETIMEDOUT`) in the benchmark, whose `requestTimeout` was
10 s, during a slow flush window on the server. Consider measuring the timeout from the last answer received on the connection
rather than per request, so a slow but progressing server is not treated as dead, and make the error say how long it waited and
how many requests were outstanding.

## What smb3-client already does better than smb2, for this use

The README and source of `smb2` document none of these for its public API, and blocktransfer's storage layer depends on them:
exclusive create, truncate (end-of-file), a no-replace rename (`rename(path, replaceIfExists = false)`), a stable file identity from
`stat` on a persistent handle, and server-held handles used as write locks. Keep them when changing anything above.

## Not worth copying yet

- smb2's learned headroom estimator (`tuning.rs`, about 100 lines of tunables) before depth 4–8 is shown insufficient.
- Multi-channel, DFS and durable-handle reconnection: not needed by blocktransfer, and `smb2` itself lists multi-channel as a gap.
- Anything that targets uploads, until a server with faster writes is available to measure against.

## How to reproduce

- smb2 CLI: `brew install vdavid/tap/smb2`, then `SMB2_USER=… SMB2_PASS=… smb2 put FILE //host/share/dir/FILE` and `smb2 get`.
- Concurrency and encryption probe: open a remote file with `client.openStorage(path, { read: true })`, then issue `handle.read(offset,
  1 MiB)` calls with 1, 4 and 8 workers sharing a counter; repeat with `encryption: 'disabled'`. The scripts used here were kept
  outside the repository and are not part of this change.
- Existing harness: `npm run bench:smb-access -- --volume /Volumes/Temp --url smb://ch@igloo.local/temp --layers io --mib 256`. It
  reads and writes one 1 MiB block at a time, so it measures the sequential case only. Its first-run report is
  `benchmarks/results/smb-access-baseline-0.2.1.md` (the direct arm hit the timeout above on one upload, so the run is marked failed;
  25 trials were valid).

## Limits of this evidence

One share, one network, 2–3 runs per cell, and server write speed that varied between sessions (our earlier `cp` upload took 12.6 s for
256 MiB, later 34–39 s). Read numbers were stable within about 10%. Direct-client numbers use the installed 0.2.2 build, not the fork's
uncommitted working tree. Nothing was changed in `smb3-client`, so the "after" measurement the plan called for has not been done.

## Companion change in blocktransfer (not upstream)

The engine awaits each 1 MiB block before issuing the next (`src/core.ts` byte loop and the local-stores range copy), so even a fixed
client would see one request in flight. Blocktransfer needs read-ahead of its own, for example a bounded queue of 4–8 outstanding
`source.read` calls, hashing and writing in order. That change belongs in this repository, and it applies to the mount as well as to
direct SMB.
