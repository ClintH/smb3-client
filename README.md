# smb3-client

[![CI](https://github.com/euricojardim/smb3-client/actions/workflows/ci.yml/badge.svg)](https://github.com/euricojardim/smb3-client/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/smb3-client.svg)](https://www.npmjs.com/package/smb3-client)

`smb3-client` is a pure-TypeScript SMB 3.x client for Node.js 20+. It speaks [MS-SMB2] directly over TCP/445 — no native bindings, no external runtime dependencies — and exposes a familiar `fs`-like promise API: `readFile`, `writeFile`, `readdir`, `stat`, `mkdir`, and friends. It is aimed at server-side Node applications that need to talk to Windows file shares without mounting a network drive.

## Contents

- [Status](#status)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [API](#api)
- [Path convention](#path-convention)
- [Errors](#errors)
- [Streaming](#streaming)
- [Watch (CHANGE_NOTIFY)](#watch-change_notify)
- [Examples](#examples)
- [Development](#development)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Status

- 108 unit tests pass.
- 10 integration tests pass against a real Windows server.
- Full v1 API surface implemented (see [API](#api) below).
- Alpha: the API may change before 1.0.

## Features

**Supported**

- Dialect negotiation: SMB 2.1, 3.0, 3.0.2, 3.1.1.
- Authentication: NTLMv2 wrapped in minimal SPNEGO. Username + password. Workgroup and local accounts; AD users when NTLMv2 is allowed by server policy.
- Message signing: HMAC-SHA256 (SMB 2.x) and AES-128-CMAC (SMB 3.x); SHA-512 pre-auth integrity for 3.1.1.
- SMB 3.x message encryption: AES-128-CCM, AES-128-GCM, AES-256-CCM, AES-256-GCM (3.1.1); AES-128-CCM (3.0 / 3.0.2). Auto-enabled on shares with `SMB2_SHAREFLAG_ENCRYPT_DATA`. Once negotiated, plaintext responses are refused (MS-SMB2 §3.2.5.1.1 downgrade protection).
- File operations: `read`, `write`, `create`, `delete`, `rename`, `mkdir`, `rmdir`, `stat`, `readdir`.
- Streaming I/O via Node `Readable` / `Writable` and `node:stream/promises` `pipeline`.
- Directory change notifications (`SMB2 CHANGE_NOTIFY`) as `AsyncIterable<ChangeEvent>`.
- Share enumeration via DCE/RPC `srvsvc.NetrShareEnum`.

**Not supported (yet)**

- Kerberos / GSSAPI mechanisms other than NTLMSSP.
- Compound requests, leases, durable handles, multi-channel.
- DFS referrals.
- NetBIOS over TCP/139.
- Recursive `rm` (caller walks the tree).
- Printer share operations.

## Requirements

- Node.js >= 20.
- A Windows SMB server reachable on TCP/445. Tested against Windows 7 / Server 2008 R2 through Windows 11 / Server 2022.
- A user with NTLMv2 credentials (workgroup or local accounts work; Active Directory users are supported when the server policy permits NTLMv2).

## Installation

```bash
npm install smb3-client
```

## Quick start

```ts
import { Client } from "smb3-client";

const client = new Client({
  host: "fileserver.lan",
  username: "alice",
  password: "...",
});

await client.connect();
const data = await client.readFile("public/readme.txt");
console.log(data.toString("utf8"));
await client.close();
```

## API

All methods are on the `Client` class exported from `smb3-client`.

### `new Client(opts: ClientOptions)`

Constructs the client. Does not open a connection.

```ts
const client = new Client({
  host: "fileserver.lan",   // required
  port: 445,                // default 445
  domain: "",               // NTLM domain; blank for workgroup/local accounts
  username: "alice",        // required
  password: "s3cr3t",       // required
  connectTimeout: 10_000,   // ms, default 10 000
  requestTimeout: 30_000,   // ms, default 30 000
  signing: "if-offered",    // "disabled" | "if-offered" | "required" (default "if-offered")
  encryption: "if-offered", // "disabled" | "if-offered" | "required" (default "if-offered")
});
```

**`signing` and `encryption` semantics:**

- `"disabled"` — opt out. The client will not sign (or encrypt) outgoing
  messages. Setup fails fast if the server's NEGOTIATE response demands the
  capability the client is disabling.
- `"if-offered"` *(default)* — opportunistic. The client signs/encrypts when
  the server agrees, otherwise proceeds without.
- `"required"` — demanded. The client refuses to proceed if the server can't
  honor the requirement, and rejects post-handshake responses that violate it.
  For signing, the requirement is also advertised in NEGOTIATE via the
  `SMB2_NEGOTIATE_SIGNING_REQUIRED` security-mode bit; for encryption the
  enforcement is at session-setup time (no supported cipher offered → error).

`signing: "required"` accepts encrypted responses as satisfying the requirement
(per MS-SMB2 §3.1.4.3, an encrypted message's inner signature is zero).
Combining `signing: "required"` with `encryption: "required"` is supported and
gives both confidentiality and integrity on every post-handshake message.

### `connect(): Promise<void>`

Opens the TCP connection, negotiates SMB dialect, and authenticates via NTLMv2.

```ts
await client.connect();
```

### `close(): Promise<void>`

Tears down all open tree connections and the session, then closes the socket.

```ts
await client.close();
```

### `readFile(path): Promise<Buffer>`
### `readFile(path, encoding): Promise<string>`

Reads the full content of a file.

```ts
const buf = await client.readFile("public/data.bin");
const text = await client.readFile("public/readme.txt", "utf8");
```

### `writeFile(path, data, encoding?): Promise<void>`

Creates or overwrites a file. `data` may be a `Buffer` or a `string` (default encoding `"utf8"`).

```ts
await client.writeFile("public/out.txt", "hello world");
await client.writeFile("public/blob.bin", Buffer.from([0xde, 0xad]));
```

### `readdir(path): Promise<string[]>`
### `readdir(path, { withFileTypes: true }): Promise<Dirent[]>`

Lists entries in a directory. Pass `{ withFileTypes: true }` to get `Dirent` objects with `isFile()` and `isDirectory()` methods plus `size` (bytes), `mtime` (last write) and `ctime` (creation). These come from the directory listing itself, so no extra requests are made. Directory sizes are usually 0, and a zero creation time (e.g. FAT/exFAT shares) reads as the Unix epoch.

```ts
const names = await client.readdir("public/inbox");
const dirents = await client.readdir("public/inbox", { withFileTypes: true });
```

### `stat(path): Promise<FileStat>`

Returns metadata for a file or directory.

```ts
const s = await client.stat("public/report.pdf");
console.log(s.size, s.mtime, s.isFile, s.isDirectory);
```

### `mkdir(path): Promise<void>`

Creates a directory (non-recursive).

```ts
await client.mkdir("public/uploads/2026");
```

### `rm(path): Promise<void>`

Deletes a file.

```ts
await client.rm("public/tmp/scratch.txt");
```

### `rmdir(path): Promise<void>`

Removes an empty directory.

```ts
await client.rmdir("public/tmp");
```

### `rename(from, to): Promise<void>`

Renames or moves a file or directory within the same share.

```ts
await client.rename("public/draft.txt", "public/final.txt");
```

### `createReadStream(path): Readable`

Returns a `Readable` stream for the file at `path`. Works with `pipeline`.

```ts
const rs = client.createReadStream("public/video.mp4");
```

### `createWriteStream(path): Writable`

Returns a `Writable` stream that creates or overwrites the file at `path`.

```ts
const ws = client.createWriteStream("public/upload.bin");
```

### `watch(path, opts?): AsyncGenerator<ChangeEvent>`

Watches a directory for changes using `SMB2 CHANGE_NOTIFY`. Yields `ChangeEvent` objects with `action` and `path` fields. Pass an `AbortSignal` to stop watching.

```ts
const ac = new AbortController();
for await (const ev of client.watch("public/inbox", { signal: ac.signal })) {
  console.log(ev.action, ev.path);
}
```

### `listShares(): Promise<ShareInfo[]>`

Enumerates all shares on the server via DCE/RPC `srvsvc.NetrShareEnum`.

```ts
const shares = await client.listShares();
for (const s of shares) console.log(s.name, s.type, s.comment);
```

## Path convention

All public paths use forward slashes. The first segment is the share name; the remainder is the path within that share.

```
"public/reports/2026/q1.xlsx"
  ^      ^^^^^^^^^^^^^^^^^
  share  path within share
```

Paths that start with `\\` or a drive letter (`C:\...`), or that contain `..`, are rejected with an `EINVAL` error.

## Errors

All library errors extend `SmbError`:

```ts
import { SmbError, SmbAuthError, SmbProtocolError } from "./src/index.js";
```

- **`SmbError`** — base class. Properties: `.status` (NT status code as a number), `.statusName` (human-readable string), `.code` (Node-style fs code, e.g. `"ENOENT"`).
- **`SmbAuthError`** — thrown when authentication fails.
- **`SmbProtocolError`** — thrown for unexpected wire-level conditions.

The `.code` property maps common NT status values to familiar fs codes: `ENOENT`, `EACCES`, `EEXIST`, `ENOTDIR`, `EISDIR`, `ENOTEMPTY`, `EBUSY`, `ENOSPC`, `EINVAL`, `ENXIO`, `ECANCELED`.

```ts
try {
  const data = await client.readFile("public/missing.txt");
} catch (err) {
  if (err instanceof SmbError && err.code === "ENOENT") {
    console.log("file does not exist");
  } else {
    throw err;
  }
}
```

## Streaming

`createReadStream` and `createWriteStream` return standard Node `Readable` and `Writable` streams compatible with `node:stream/promises` `pipeline`.

```ts
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { createReadStream, createWriteStream } from "node:fs";

// Upload a local file to the share.
await pipeline(
  createReadStream("/local/path/video.mp4"),
  client.createWriteStream("public/videos/video.mp4"),
);

// Download from the share to a local file.
await pipeline(
  client.createReadStream("public/videos/video.mp4"),
  createWriteStream("/local/path/video.mp4"),
);
```

## Watch (CHANGE_NOTIFY)

`client.watch()` wraps `SMB2 CHANGE_NOTIFY` as an async generator. Each yielded event has an `action` (`"added"`, `"removed"`, `"modified"`, `"renamedOldName"`, `"renamedNewName"`) and a `path` relative to the share root.

Use an `AbortController` to stop the watch:

```ts
const ac = new AbortController();
// Stop after 10 seconds.
setTimeout(() => ac.abort(), 10_000);

for await (const ev of client.watch("public/inbox", { signal: ac.signal })) {
  console.log(`${ev.action}: ${ev.path}`);
}
```

Pass `recursive: true` to watch subdirectories as well (subject to server support).

## Examples

The `client_example/` directory contains ten runnable scripts. See [`client_example/README.md`](https://github.com/euricojardim/smb3-client/blob/main/client_example/README.md) for full details.

| Script | Description |
|---|---|
| `01-negotiate.ts` | Low-level TCP connect + SMB NEGOTIATE — dialect, server GUID, max sizes |
| `02-stat.ts` | `stat()` a temp file — inspect size, timestamps, attributes |
| `03-read-file.ts` | Write known content, read it back, assert equality |
| `04-write-and-read.ts` | 64 KiB random round-trip with SHA-256 verification |
| `05-list-directory.ts` | `readdir()` in both name and Dirent forms |
| `06-rename.ts` | Rename a file within a share, verify before/after |
| `07-mkdir-rmdir.ts` | Create and remove an empty directory |
| `08-stream-large-file.ts` | 4 MiB `pipeline` upload + download with throughput stats |
| `09-watch.ts` | CHANGE_NOTIFY async iterator with AbortController |
| `10-list-shares.ts` | DCE/RPC `NetrShareEnum` — list all shares |

Run any example:

```bash
# Load credentials from .env (copy .env.example and fill in your values).
set -a && . ./.env && set +a

npx tsx client_example/01-negotiate.ts
npx tsx client_example/05-list-directory.ts
```

The examples expect these env vars:

| Variable | Required | Description |
|---|---|---|
| `SMB_TEST_HOST` | yes | Server hostname or IP |
| `SMB_TEST_PORT` | no | TCP port (default `445`) |
| `SMB_TEST_DOMAIN` | no | NTLM domain (blank for workgroup/local) |
| `SMB_TEST_USERNAME` | yes | Username |
| `SMB_TEST_PASSWORD` | yes | Password |
| `SMB_TEST_SHARE` | yes | Share name, e.g. `public` |

## Development

```bash
npm test                  # unit tests (vitest)
npm run test:integration  # integration tests (requires env vars above)
npm run verify            # typecheck + lint + unit tests
npm run build             # compile to dist/
```

Integration tests are skipped automatically when the env vars are absent.

Design specification: [`docs/superpowers/specs/2026-05-09-node-smb3-client-design.md`](https://github.com/euricojardim/smb3-client/blob/main/docs/superpowers/specs/2026-05-09-node-smb3-client-design.md).

## Architecture

The client is built as a layered pipeline, each layer exposing a narrow interface to the layer above:

```
Client          — public fs-like API
  Tree          — share (TREE_CONNECT), translates share paths
    Open        — file handles (CREATE / CLOSE), read, write, stat, readdir, notify
    Session     — NTLMv2 authentication, session keys, signing setup
  Connection    — SMB2 framing, message dispatch, credit flow, signing verification
    TcpTransport — raw TCP socket + 4-byte length framer
```

- **TcpTransport** (`src/transport/socket.ts`) — wraps `node:net`, emits parsed SMB frames.
- **Connection** (`src/connection/connection.ts`) — tracks pending requests by message ID, handles async interim responses, manages the credit window, and accumulates the SHA-512 pre-auth hash.
- **Session** (`src/session/session.ts`) — drives the NTLM/SPNEGO exchange; derives signing keys.
- **Tree** (`src/tree/tree.ts`) — manages a single `TREE_CONNECT` and provides helpers used by `Open`.
- **Open** (`src/open/open.ts`) — lifecycle around a single `CREATE`/`CLOSE` pair; sub-modules handle read, write, readdir, streaming, and change notification.
- **Client** (`src/client.ts`) — facade that lazily connects trees per share and exposes the public API.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://github.com/euricojardim/smb3-client/blob/main/CONTRIBUTING.md) for
development setup, coding conventions, and the PR checklist.

## Security

To report a vulnerability, see [SECURITY.md](https://github.com/euricojardim/smb3-client/blob/main/SECURITY.md). Do not open a public issue.

## License

MIT — see [LICENSE](./LICENSE).
