# node-smb3 — Design Spec

**Status:** Draft  
**Date:** 2026-05-09  
**Owner:** euricojardim@gmail.com

## 1. Goal & Scope

A practical SMB3 file-sharing client for Node.js. Pure TypeScript (ESM, Node 20+), no native dependencies. The public API is fs-like and promise-based; under the hood it speaks the [MS-SMB2] protocol directly over TCP/445.

### In scope
- TCP/445 transport (no NetBIOS over TCP/139, no name service).
- Dialects negotiated: SMB 2.1, 3.0, 3.0.2, 3.1.1.
- Authentication: NTLMv2 wrapped in a minimal SPNEGO token. Username + password (or NT hash) only.
- Message signing (HMAC-SHA256 for 2.x, AES-128-CMAC for 3.x; SHA-512 pre-auth integrity hash for 3.1.1).
- SMB 3.x message encryption (AES-128/256, CCM/GCM AEAD modes; auto-enabled for shares with `SMB2_SHAREFLAG_ENCRYPT_DATA`).
- File operations: read, write, create, delete, rename, mkdir, rmdir.
- Directory listing and stat.
- Streaming I/O for large files (Node `Readable` / `Writable`).
- Share enumeration via DCE/RPC `srvsvc.NetrShareEnum` over the `IPC$` named pipe.
- Directory change notifications via `SMB2_CHANGE_NOTIFY`, surfaced as an `AsyncIterable<ChangeEvent>`.

### Out of scope (v1, deliberate)
Kerberos / GSSAPI mechs other than NTLMSSP, compound requests, leases, durable handles, multi-channel, oplocks, DFS referrals, NetBIOS over TCP/139, IPv6-specific fallback logic, printer/named-pipe ops beyond `srvsvc`, server-to-server copy (`FSCTL_SRV_COPYCHUNK`), recursive `rm`. Anonymous / guest sessions.

### Target servers
- Windows 10 / 11 / Server 2016+ (negotiates 3.1.1).
- Windows 7 / 8 / Server 2008–2012 (negotiates 2.1 or 3.0).

## 2. Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Client (fs-like, promise API)                          │
│    readFile, writeFile, readdir, stat, mkdir, rm,       │
│    rename, createReadStream, createWriteStream,         │
│    watch(path) → AsyncIterable<ChangeEvent>             │
│    listShares()                                         │
└──────────────────────┬──────────────────────────────────┘
                       │ uses
┌──────────────────────▼──────────────────────────────────┐
│  Tree (one per share)        Open (one per file/dir)    │
│    treeConnect / disconnect    create, read, write,     │
│    queryDirectory              close, queryInfo,        │
│                                changeNotify             │
└──────────────────────┬──────────────────────────────────┘
                       │ owned by
┌──────────────────────▼──────────────────────────────────┐
│  Session                                                │
│    NTLMSSP exchange (over SPNEGO), session key,         │
│    signing key derivation, session-id                   │
└──────────────────────┬──────────────────────────────────┘
                       │ owned by
┌──────────────────────▼──────────────────────────────────┐
│  Connection                                             │
│    Negotiate (dialect, capabilities, pre-auth hash),    │
│    MessageId allocator, credit window, async-id mgmt,   │
│    request/response correlation, signing apply/verify   │
└──────────────────────┬──────────────────────────────────┘
                       │ uses
┌──────────────────────▼──────────────────────────────────┐
│  Transport                                              │
│    net.Socket → length-prefixed SMB2 framing            │
│    (4-byte NetBIOS-style header: 0x00 + 24-bit length)  │
└─────────────────────────────────────────────────────────┘
```

Each layer owns the state the spec assigns it. Layers above only see the API of the layer directly below; no reaching through. `Client` is the only public class; the other layers are internal but exported for advanced use.

## 3. Module layout

```
src/
  index.ts                    # public exports: Client, types, errors
  client.ts                   # fs-like facade (Client)
  transport/
    socket.ts                 # net.Socket wrapper, NBSS-style framer
    framer.ts                 # length-prefix encode/decode (pure)
  connection/
    connection.ts             # Connection: negotiate, send/recv, credits
    negotiate.ts              # NEGOTIATE encode/decode + dialect logic
    credits.ts                # credit window accounting
    signing.ts                # HMAC-SHA256 + AES-CMAC sign/verify
    encryption.ts             # SMB 3.x TRANSFORM_HEADER + AES-CCM/GCM AEAD
    preauth.ts                # SMB 3.1.1 pre-auth integrity hash
  session/
    session.ts                # Session lifecycle, key derivation
    ntlm.ts                   # NTLMSSP NEGOTIATE/CHALLENGE/AUTH
    spnego.ts                 # minimal SPNEGO/GSS wrapper around NTLM
  tree/
    tree.ts                   # TreeConnect, share path resolution
  open/
    open.ts                   # CREATE/CLOSE, file handle lifecycle
    read.ts                   # READ + streaming Readable
    write.ts                  # WRITE + streaming Writable
    query.ts                  # QUERY_INFO, QUERY_DIRECTORY, set info
    changeNotify.ts           # CHANGE_NOTIFY async iterator
    delete.ts                 # delete-on-close, rename via SET_INFO
  rpc/
    dcerpc.ts                 # minimal DCE/RPC bind + request framing
    srvsvc.ts                 # NetrShareEnum (for listShares)
  wire/
    buffer.ts                 # typed read/write helpers (LE)
    smb2-header.ts            # SYNC + ASYNC header encode/decode
    commands.ts               # opcode enum, status codes (NTSTATUS)
    structs/                  # per-command request/response structs
      negotiate.ts
      sessionSetup.ts
      treeConnect.ts
      create.ts
      read.ts
      write.ts
      close.ts
      queryDirectory.ts
      queryInfo.ts
      setInfo.ts
      changeNotify.ts
      ioctl.ts
  errors.ts                   # SmbError class, NTSTATUS → message
  types.ts                    # public types (FileStat, ChangeEvent, etc.)
test/
  unit/                       # struct codecs, signing vectors, NTLM vectors
  integration/                # opt-in, run against the Windows VM
  fixtures/                   # captured wire bytes
```

Three reasons for this shape:
1. `wire/structs/` is pure encode/decode — easy to unit-test against captured bytes from Wireshark.
2. `connection/`, `session/`, `tree/`, `open/` mirror the protocol object model so each file has one responsibility.
3. `rpc/srvsvc.ts` is isolated because DCE/RPC is its own protocol that just happens to ride over SMB named pipes — keeping it out of the SMB core avoids tangling.

## 4. Wire layer & framing

**TCP transport.** Open `net.Socket` to `host:445`. Each SMB2 message on the wire is preceded by a 4-byte "Direct TCP" header: 1 byte zero + 3-byte big-endian length. The framer reads from the socket, accumulates bytes, and emits whole SMB2 messages upward; on send it prepends the 4-byte header.

**SMB2 header (64 bytes).** Two flavors:
- **SYNC** header for most requests/responses. Fields: `ProtocolId(0xFE 'S' 'M' 'B')`, `StructureSize(64)`, `CreditCharge`, `Status`/`ChannelSequence`, `Command`, `CreditRequest`/`CreditResponse`, `Flags`, `NextCommand`, `MessageId`, `Reserved`/`TreeId`, `SessionId`, `Signature(16)`.
- **ASYNC** header used when the server returns `STATUS_PENDING` (interim) and later the final response. `AsyncId` replaces the `Reserved/TreeId` field. Required for `CHANGE_NOTIFY`.

`smb2-header.ts` exposes `encodeHeader(fields)` / `decodeHeader(buf)` and a discriminator that tells callers whether a received frame is SYNC or ASYNC based on the `SMB2_FLAGS_ASYNC_COMMAND` bit.

**Buffer helpers (`wire/buffer.ts`).** Tiny `Reader` / `Writer` wrappers around `Buffer` with cursor + LE accessors for `u8/u16/u32/u64`, plus UTF-16LE string helpers (SMB2 uses UTF-16LE for paths, no null terminator) and a remaining view for variable-length fields. All struct codecs use these — no raw `buf.readUInt32LE(offset)` scattered around.

**Per-command structs.** Each file in `wire/structs/` exports a typed `Request` interface, an `encode(req): Buffer`, a `Response` interface, and a `decode(buf): Response`. Pure functions, no I/O — unit tests feed them captured bytes and golden objects.

**Compound requests** (`NextCommand`) are skipped for v1; can be added later without breaking the layered design.

## 5. Connection layer (negotiate, multiplexing, credits, signing)

### Negotiate
On `connection.open()`:
1. Send `SMB2 NEGOTIATE` advertising dialects `0x0210, 0x0300, 0x0302, 0x0311`, a fresh 16-byte `ClientGuid`, and capabilities (`DFS=0`, `LARGE_MTU=1`, `LEASING=0`, `MULTI_CHANNEL=0`, `ENCRYPTION=0`).
2. For SMB 3.1.1, append a `PreauthIntegrityCapabilities` context (HashAlgorithm=SHA-512, fresh 32-byte salt) and an `EncryptionCapabilities` context advertising no ciphers (we don't support encryption).
3. Server picks a dialect. Store `DialectRevision`, `ServerGuid`, `MaxTransactSize/MaxReadSize/MaxWriteSize`, `SecurityMode`, `Capabilities`, and the SPNEGO blob.
4. If dialect is 3.1.1, initialize `PreauthIntegrityHashValue = SHA-512(zeros || NEGOTIATE_request || NEGOTIATE_response)`. The hash continues through `SESSION_SETUP` until the session is authenticated.

### Message correlation
`Map<MessageId, PendingRequest>` where each `PendingRequest` carries `{ resolve, reject, sentAt, expectsAsync }`. On a SYNC response, `MessageId` matches → resolve. On an interim `STATUS_PENDING`, the server assigns an `AsyncId`; we record it on the pending entry and keep waiting for the final ASYNC response that quotes the same `AsyncId`. Used by `CHANGE_NOTIFY` and any other long-running op.

### Credits
A single integer `availableCredits`. Each request specifies a `CreditCharge` (1 for normal ops; for `READ`/`WRITE` larger than 64 KiB, `CreditCharge = ceil(payload/64KiB)`) and a `CreditRequest` to refill. The connection refuses to send a request whose charge exceeds available credits; instead it parks it in a small FIFO queue and drains as responses come back (every response carries `CreditResponse`). A `waitForCredits(n)` primitive in `credits.ts`.

### Signing
When a session is established, every non-`NEGOTIATE`/non-`SESSION_SETUP` request sets `SMB2_FLAGS_SIGNED`, zeros the `Signature` field, computes the MAC over the entire SMB2 message (header+body+padding), and writes the result into `Signature`. Algorithm by dialect:
- 2.1: HMAC-SHA256 with `SigningKey` (= `SessionKey` for 2.x).
- 3.0 / 3.0.2: AES-128-CMAC with `SigningKey = KDF(SessionKey, "SMB2AESCMAC", "SmbSign")`.
- 3.1.1: AES-128-CMAC with `SigningKey = KDF(SessionKey, "SMBSigningKey", PreauthHash)`.

Incoming responses get verified the same way; a mismatch is a fatal connection error (close + reject all pending).

### Encryption (SMB 3.x)
When the session has encryption keys (negotiated via NEGOTIATE's `EncryptionCapabilities` context for 3.1.1 or the `SMB2_GLOBAL_CAP_ENCRYPTION` capability bit for 3.0/3.0.2), every non-`NEGOTIATE`/non-`SESSION_SETUP` request that the client decides to encrypt is wrapped in a 52-byte `SMB2 TRANSFORM_HEADER` (`0xFD 'SMB'` ProtocolId) followed by AEAD ciphertext over the original SMB2 PDU. Key derivation reuses the SP800-108 KDF: 3.0/3.0.2 uses labels `"SMB2AESCCM"` with contexts `"ServerIn "` (client→server) and `"ServerOut"` (server→client); 3.1.1 uses labels `"SMBC2SCipherKey"` / `"SMBS2CCipherKey"` with the pre-auth hash as context. Nonces are a per-connection counter zero-padded to 11 bytes (CCM) or 12 bytes (GCM). The AAD is bytes 20..52 of the transform header (Nonce..SessionId). Encryption is mutually exclusive with signing for the same PDU — the inner SMB2 header is left unsigned, integrity is carried in the transform header's auth tag. Per MS-SMB2 §3.2.5.5, a tree connection whose response carries `SMB2_SHAREFLAG_ENCRYPT_DATA` mandates encryption on every subsequent request against that tree.

**Downgrade protection.** Once `Session.EncryptData` is TRUE (i.e. we agreed to encrypt during `SESSION_SETUP`), the connection refuses any inbound plaintext SMB2 response other than `SESSION_SETUP` and fatally fails per MS-SMB2 §3.2.5.1.1. This blocks an active attacker — or a buggy server — from silently stripping the transform header after the negotiation succeeded.

### Disconnect
`client.close()` sends `LOGOFF` per session and `TREE_DISCONNECT` per cached tree, then ends the socket. Idempotent.

## 6. Session layer (NTLMv2 over SPNEGO)

### SPNEGO wrapper
SMB2 carries the auth blob as a GSS-API token. We use a minimal SPNEGO encoder/decoder — just enough ASN.1 DER for `NegTokenInit` (initial) and `NegTokenResp` (continuation). Inside the token the only mech we offer or accept is NTLMSSP (OID `1.3.6.1.4.1.311.2.2.10`). No other mechs, no general-purpose ASN.1 library.

### NTLMSSP three-message flow

1. **NEGOTIATE_MESSAGE (type 1).** Client → server. Flags: `NEGOTIATE_UNICODE | NEGOTIATE_OEM | REQUEST_TARGET | NEGOTIATE_SIGN | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_NTLM | NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_TARGET_INFO | NEGOTIATE_VERSION | NEGOTIATE_128 | NEGOTIATE_KEY_EXCH | NEGOTIATE_56`. Wrap in SPNEGO `NegTokenInit` and send as `SESSION_SETUP` request.

2. **CHALLENGE_MESSAGE (type 2).** Server → client. Carries the 8-byte server challenge and the `TargetInfo` AV_PAIR list (domain name, server name, DNS names, timestamp, etc.). Server replies with `STATUS_MORE_PROCESSING_REQUIRED` and a `SessionId` we keep using.

3. **AUTHENTICATE_MESSAGE (type 3).** Client → server. Compute:
   - `ResponseKeyNT = HMAC-MD5(MD4(UTF-16LE(password)), UPPER(username) || domain)`
   - `temp = 0x01 0x01 || 6 bytes zero || timestamp(8) || clientChallenge(8) || 0x00000000 || TargetInfoBytes || 0x00000000`
   - `NTProofStr = HMAC-MD5(ResponseKeyNT, ServerChallenge || temp)`
   - `NtChallengeResponse = NTProofStr || temp`
   - `LmChallengeResponse = HMAC-MD5(ResponseKeyNT, ServerChallenge || clientChallenge) || clientChallenge` (24 bytes; mostly ignored by modern servers but included)
   - `KeyExchangeKey = HMAC-MD5(ResponseKeyNT, NTProofStr)` (NTLMv2 session base key)
   - `ExportedSessionKey` = 16 random bytes (because `NEGOTIATE_KEY_EXCH` is set), encrypted as `EncryptedRandomSessionKey = RC4(KeyExchangeKey, ExportedSessionKey)`. `ExportedSessionKey` becomes the SMB2 `SessionKey`.
   - MIC: `HMAC-MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)` placed in the AUTHENTICATE message's MIC field. Modern Windows requires this.

   Wrap in SPNEGO `NegTokenResp` and send as second `SESSION_SETUP`.

### Server responses to AUTHENTICATE
`STATUS_SUCCESS` finishes the handshake. `STATUS_LOGON_FAILURE` / `STATUS_PASSWORD_EXPIRED` / `STATUS_ACCOUNT_DISABLED` etc. are surfaced as typed `SmbAuthError` subclasses.

### Pre-auth integrity (3.1.1)
Each session-setup request and response is fed into the rolling SHA-512 hash before we move to AUTHENTICATE. The hash value at the point the session is authenticated is what `KDF` uses to derive the signing key.

### Signing key derivation
- 2.1: `SigningKey = SessionKey`.
- 3.x: SP800-108 KDF in counter mode with HMAC-SHA256.
  - 3.0 / 3.0.2: `Label="SMB2AESCMAC"\0`, `Context="SmbSign"\0`.
  - 3.1.1: `Label="SMBSigningKey"\0`, `Context=PreauthHash`.

### Credentials API
The `Client` constructor takes `{ host, port?, domain?, username, password }` (or `{ ntlmHash }` for pass-the-hash on the lab machine — useful for testing).

## 7. Tree, Open, and file operations

### TreeConnect
`connection.tree("\\\\server\\share")` sends `SMB2 TREE_CONNECT` with the UTF-16LE share path. Response gives `TreeId`, `ShareType` (DISK / PIPE / PRINT), and `ShareFlags`. One `Tree` per share path, cached on `Client`. The `IPC$` tree is special — `listShares()` opens it on demand and the user never sees it.

### Open (file/dir handle)
`tree.create(path, options)` sends `SMB2 CREATE` with:
- `DesiredAccess` (e.g., `FILE_READ_DATA | READ_ATTRIBUTES`; `GENERIC_WRITE | DELETE` for write).
- `FileAttributes`, `ShareAccess` (default `READ|WRITE|DELETE`).
- `CreateDisposition` (`OPEN`, `CREATE`, `OVERWRITE_IF`, `OPEN_IF`, `SUPERSEDE`).
- `CreateOptions` (`FILE_DIRECTORY_FILE` vs `FILE_NON_DIRECTORY_FILE`, `FILE_DELETE_ON_CLOSE` when needed).
- Path as UTF-16LE, no leading `\`.
- No create contexts in v1 (no leases, no durable handles). `RequestedOplockLevel = NONE`.

Response carries `FileId` (16 bytes: persistent + volatile), end-of-file, timestamps, and a basic file info struct. `Open` wraps the handle and ensures `close()` runs on success or failure.

### Read
`open.read(offset, length)` sends `SMB2 READ` with the calculated `CreditCharge`. Reads larger than `MaxReadSize` are split inside the read layer. `createReadStream(path)` returns a `Readable` that pipelines several in-flight `READ`s up to a small concurrency limit (default ≤ 8, capped by available credits) and pushes chunks in offset order.

### Write
`open.write(offset, buffer)` sends `SMB2 WRITE`. Same chunking against `MaxWriteSize` and same credit charging. `createWriteStream(path)` returns a `Writable` that buffers up to `MaxWriteSize`, allows multiple in-flight writes, and `close()`s the handle on `final()`.

### QueryDirectory (readdir/stat)
Open a directory handle, then `SMB2 QUERY_DIRECTORY` with `FileInformationClass = FileIdBothDirectoryInformation` (gives names, sizes, timestamps, attributes, and FileId in one shot). Repeat with the previous response's last filename until `STATUS_NO_MORE_FILES`. `stat(path)` is a single-entry `QUERY_DIRECTORY` against the parent — cheaper than open + `QUERY_INFO`.

### Mkdir / rm / rename
- `mkdir`: `CREATE` with `FILE_DIRECTORY_FILE` and `CreateDisposition=CREATE`, then `CLOSE`.
- `rm` (file): `CREATE` with `DELETE` access and `FILE_DELETE_ON_CLOSE`, then `CLOSE`.
- `rmdir`: same pattern with `FILE_DIRECTORY_FILE`. No recursive delete in v1.
- `rename`: `CREATE` with `DELETE | READ_ATTRIBUTES`, `SET_INFO` with `FileRenameInformation` (target path UTF-16LE, `ReplaceIfExists` flag), `CLOSE`.

### CHANGE_NOTIFY
`client.watch(path, options)` returns an `AsyncIterable<ChangeEvent>` plus `AbortSignal`-driven cancellation:
1. Open the directory with `FILE_LIST_DIRECTORY` access.
2. Send `SMB2 CHANGE_NOTIFY` with `CompletionFilter` (file name, dir name, attributes, size, last-write, security — configurable; sensible default covers create/modify/delete/rename) and `Flags = WATCH_TREE` if `recursive: true`.
3. Server returns `STATUS_PENDING` → we get an `AsyncId`. The pending request stays alive.
4. When changes occur, server sends an ASYNC response with a list of `FILE_NOTIFY_INFORMATION` records (action + filename). We yield each as a typed `ChangeEvent`.
5. Immediately re-arm by sending another `CHANGE_NOTIFY` (the protocol is one-shot per request).
6. Cancellation: `SMB2 CANCEL` referencing the `AsyncId`, then `CLOSE` the directory handle. Server returns `STATUS_CANCELLED`.

### listShares()
Connect to `\\server\IPC$`, `CREATE` the named pipe `\srvsvc`, do a DCE/RPC `Bind` (interface UUID `4b324fc8-1670-01d3-1278-5a47bf6ee188`, version 3.0), then `NetrShareEnum` (opnum 15) with info level 1. Parse the share list. The DCE/RPC fragment encoder lives in `rpc/dcerpc.ts`; `srvsvc.ts` only knows the `NetrShareEnum` request/response NDR layout.

## 8. Public API

```ts
import { Client } from "node-smb3";

const client = new Client({
  host: "fileserver.lan",
  port: 445,            // optional, default 445
  domain: "CORP",       // optional; "" or omit for local accounts
  username: "alice",
  password: "...",
  // ntlmHash: Buffer,  // alt to password (pass-the-hash, lab use)
  connectTimeout: 10_000,
  requestTimeout: 30_000,
  signing: "required",  // "required" | "if-offered"; default "required"
  encryption: "if-offered", // "required" | "if-offered" | "disabled"; default "if-offered"
});

await client.connect();

// fs-like ops — paths look like "share/dir/file.txt" (forward slashes,
// share is the first segment)
await client.readFile("public/readme.txt");           // → Buffer
await client.readFile("public/readme.txt", "utf8");   // → string
await client.writeFile("public/out.bin", buf);
await client.readdir("public/dir");                   // → string[]
await client.readdir("public/dir", { withFileTypes: true }); // → Dirent[]
await client.stat("public/file.txt");                 // → FileStat
await client.mkdir("public/newdir");
await client.rm("public/file.txt");
await client.rmdir("public/emptydir");
await client.rename("public/a.txt", "public/b.txt");

// streaming
const rs = client.createReadStream("public/big.iso");
rs.pipe(fs.createWriteStream("./big.iso"));

const ws = client.createWriteStream("public/upload.bin");
fs.createReadStream("./upload.bin").pipe(ws);

// share enumeration
const shares = await client.listShares();
// → [{ name: "public", type: "disk", comment: "..." }, ...]

// directory watch
const ac = new AbortController();
for await (const ev of client.watch("public/inbox", {
  recursive: true,
  signal: ac.signal,
})) {
  // ev.action: "added"|"removed"|"modified"|"renamedOldName"|"renamedNewName"
  // ev.path:   share-relative
}

await client.close();
```

### Public types

```ts
export interface FileStat {
  size: number;          // bigint via statBig() if > MAX_SAFE_INTEGER
  isFile: boolean;
  isDirectory: boolean;
  attributes: number;    // raw FILE_ATTRIBUTE_* bitmap
  readonly: boolean;
  hidden: boolean;
  system: boolean;
  archive: boolean;
  ctime: Date;           // creation
  atime: Date;           // last access
  mtime: Date;           // last write
  changeTime: Date;      // last metadata change
}

export interface Dirent {
  name: string;
  isFile(): boolean;
  isDirectory(): boolean;
  size: number;          // EndOfFile, clamped to MAX_SAFE_INTEGER
  mtime: Date;           // last write
  ctime: Date;           // creation
}

export interface ShareInfo {
  name: string;
  type: "disk" | "ipc" | "print" | "special";
  comment: string;
}

export type ChangeAction =
  | "added" | "removed" | "modified"
  | "renamedOldName" | "renamedNewName";

export interface ChangeEvent {
  action: ChangeAction;
  path: string;          // share-relative
}
```

### File sizes
Exposed as `number` if it fits in `Number.MAX_SAFE_INTEGER` (8 PiB — fine for any real file); otherwise `stat()` throws and `statBig()` returns a `bigint` size. Defaulting to `number` matches `node:fs` ergonomics.

### Errors
A single `SmbError` class with `.status` (NTSTATUS hex string), `.statusName` (e.g. `"STATUS_OBJECT_NAME_NOT_FOUND"`), `.message`, and `.code` (a stable, fs-like code: `"ENOENT"`, `"EACCES"`, `"EEXIST"`, `"ENOTDIR"`, `"EISDIR"`, `"ENOTEMPTY"`, etc.). Auth errors: `SmbAuthError extends SmbError`. Connection-level / signing failures: `SmbProtocolError extends SmbError` — fatal; the client transitions to a closed state.

### Concurrency
A single `Client` is safe to use concurrently — every public method is independent; serialization of writes to the socket happens inside `Connection`. Reusing the same `Client` for many operations is the recommended pattern. No connection pool in v1.

## 9. Error handling & lifecycle

### NTSTATUS → fs code mapping

| NTSTATUS                                                       | fs code      |
|----------------------------------------------------------------|--------------|
| OBJECT_NAME_NOT_FOUND, OBJECT_PATH_NOT_FOUND, NO_SUCH_FILE     | ENOENT       |
| OBJECT_NAME_COLLISION                                          | EEXIST       |
| ACCESS_DENIED, PRIVILEGE_NOT_HELD                              | EACCES       |
| SHARING_VIOLATION, FILE_LOCK_CONFLICT                          | EBUSY        |
| NOT_A_DIRECTORY                                                | ENOTDIR      |
| FILE_IS_A_DIRECTORY                                            | EISDIR       |
| DIRECTORY_NOT_EMPTY                                            | ENOTEMPTY    |
| DISK_FULL                                                      | ENOSPC       |
| NETWORK_NAME_DELETED, BAD_NETWORK_NAME                         | ENXIO        |
| INVALID_PARAMETER                                              | EINVAL       |
| (unmapped)                                                     | (raw status) |

Anything else falls through with the raw status name on `.statusName`; `.code` is left undefined so callers don't accidentally branch on a wrong synonym.

### Cancellation
Every public method takes `{ signal: AbortSignal }`. On abort:
- If the request is queued (waiting on credits), drop it from the queue and reject with `AbortError`.
- If it's in-flight (sent, awaiting response), send `SMB2 CANCEL` referencing the `MessageId` (or `AsyncId` for ASYNC), reject with `AbortError`. The eventual `STATUS_CANCELLED` response is consumed silently.

### Timeouts
Per-request timeout (default 30 s) is implemented as a wrapper that arms a timer and `controller.abort()`s on fire. `connectTimeout` is separate and fires only during the TCP+negotiate+session-setup phase.

### Connection loss
Socket `error` or `close` while operations are pending → reject all pending with `SmbProtocolError({ code: "ECONNRESET" })`. `Client` transitions to `closed` (terminal). New calls reject immediately. No auto-reconnect in v1; callers can construct a new `Client`.

### Signature failures
A response whose signature doesn't verify is treated as a protocol error: log, close the connection, reject all pending. We never silently accept unsigned responses once a session is established.

### STATUS_PENDING handling
The interim response binds `AsyncId` to the pending request; the caller's promise stays unresolved until the final response. The interim response refunds credits the request charged (server policy via `CreditResponse`), so long-poll `CHANGE_NOTIFY`s don't lock credits forever.

### Path normalization
Public paths use `/`. We split on `/`, take the first segment as the share name, join the rest with `\`, encode UTF-16LE. Reject paths with `..`, drive letters, or `\\` prefix at the API boundary with `EINVAL`. No symlink following — SMB has its own reparse-point semantics, out of scope for v1.

### Resource cleanup
`client.close()` flushes pending requests with `AbortError`, sends `LOGOFF` per session, sends `TREE_DISCONNECT` per cached tree, ends the socket, transitions to `closed`. Idempotent.

### File handle leaks
Every public op that opens a handle uses an internal `withOpen(opts, fn)` helper that always issues `CLOSE` (even on error path). Streaming helpers attach `CLOSE` to `Readable.destroy` / `Writable.final`/`destroy`.

### Watcher lifecycle
When the consumer returns/breaks out of the `for-await`, or aborts the signal, we `SMB2 CANCEL` the in-flight `CHANGE_NOTIFY`, wait for `STATUS_CANCELLED`, then `CLOSE` the directory handle. The iterator's `return()` does this in protocol terms (no extra round trips after cancel completes).

## 10. Testing strategy

### Unit tests — pure codec layer
Each file in `wire/structs/*` and `wire/smb2-header.ts` gets a paired test that:
- Encodes a typed request object to bytes, asserts it matches a captured/golden buffer.
- Decodes a captured response buffer, asserts it matches an expected typed object.
Captures come from Wireshark dumps off the Windows VM, saved as `test/fixtures/<command>-<scenario>.bin`. Round-trip property: `decode(encode(x))` deep-equals `x` for round-trippable types.

### Unit tests — crypto
Known-answer tests against vectors from MS-SMB2 / MS-NLMP appendices and public SMB3 sample vectors:
- HMAC-SHA256 sign/verify on a known SMB2 message.
- AES-CMAC sign/verify.
- SP800-108 KDF outputs (signing key derivation for 3.0/3.0.2 and 3.1.1).
- SHA-512 pre-auth hash chain.
- NTLMv2 `NTProofStr` / `KeyExchangeKey` / `ExportedSessionKey` / MIC against canonical NTLM test vectors.

### Unit tests — DCE/RPC `srvsvc`
Encode/decode `NetrShareEnum` request and response NDR against captured bytes. Three captures: empty share list, single share, many shares (covers NDR pointer / conformance / varying-array edge cases).

### Unit tests — pure layers with a fake transport
A `FakeTransport` accepts scripted send-then-respond pairs. We feed it: a successful negotiate sequence, a session setup that needs two round trips, a `CHANGE_NOTIFY` that returns `STATUS_PENDING` then later an ASYNC response, a credit-starvation scenario, a signature mismatch. Each scenario is a small test. This catches state-machine bugs without a real server.

### Integration tests — real Windows VM (opt-in)
A `test/integration/` suite gated on `SMB_TEST_HOST` etc. env vars, run manually or in a separate CI job. Covers:
- Connect + auth against modern Windows (3.1.1 dialect) and legacy (2.1 / 3.0 if a Win2008/2012 VM is available).
- Round-trip read/write of a small file, of a > MaxReadSize file (forces chunking), of a file with non-ASCII filename.
- `readdir` against a directory with 2k entries (forces multi-round `QUERY_DIRECTORY`).
- `mkdir` / `rmdir` / `rename` / `rm` happy paths and the major error mappings (ENOENT, EEXIST, EACCES, EBUSY, ENOTEMPTY).
- `listShares` returns the expected shares.
- `watch()`: create a file remotely (out-of-band over SMB or via RDP), assert the iterator yields the expected `ChangeEvent`. Cancel via `AbortController`; assert the handle closes and no events arrive after.
- Streaming: pipe a 1 GiB file in each direction; assert byte-for-byte and that memory stays bounded.

### Conformance fixtures
`test/fixtures/captures/` holds named pcaps and extracted single messages. Re-using these across unit tests keeps the codecs honest against real wire bytes, not just our own encoder's output.

### Running
- `npm test` → unit only.
- `npm run test:integration` → reads `.env.test` for `SMB_TEST_HOST`, `SMB_TEST_DOMAIN`, `SMB_TEST_USERNAME`, `SMB_TEST_PASSWORD`, `SMB_TEST_SHARE`. Skipped silently if env vars are missing.

### Tooling
Vitest (fast TS, ESM-native, good fixtures support). Prettier + ESLint with `@typescript-eslint`. `tsc --noEmit` in CI.

## 11. References

- [MS-SMB2] Server Message Block (SMB) Protocol Versions 2 and 3 — Microsoft Open Specifications.
- [MS-NLMP] NT LAN Manager (NTLM) Authentication Protocol.
- [MS-SPNG] Simple and Protected GSS-API Negotiation Mechanism.
- [MS-SRVS] Server Service Remote Protocol (`NetrShareEnum`).
- [MS-DTYP] / [MS-RPCE] Common data types and DCE/RPC encoding.
- NIST SP 800-108 — KDF in counter mode.

## Update 2026-05-11: signing is now a functional tri-state

`ClientOptions.signing` accepts `"disabled" | "if-offered" | "required"` and
behaves analogously to `ClientOptions.encryption`. See
`docs/superpowers/specs/2026-05-11-signing-tri-state-alignment-design.md` for
the design.
